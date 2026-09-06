use super::{live_session::LiveEnrollmentSession, runtime};
use crate::application::provider_credential_enrollment::{
    DaemonProtectedCredentialEnrollmentSession, InitialCredentialExchange,
};
use crate::protected_activation::ProtectedActivationChannel;
use runne_api::{
    LaunchAuthorityError, ProtectedActivationKeys, ProtectedCredentialEnrollmentOwnedLaunchV3,
};
#[cfg(target_os = "macos")]
use runne_api::{
    QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1,
    QualificationRunContextRelayBindingV1, QualificationRunContextRelayDirectionV1,
};
use runne_application::local_session::LocalSessionService;
#[cfg(target_os = "macos")]
use runne_native_qualification::{
    QualificationAdmissionRelayCodecV1, QualificationAdmissionVerifier,
    QualificationFaultRelayCodecV1, QualificationRunContextRelayCodecV1,
};
use std::sync::Mutex;
use zeroize::Zeroizing;

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod connected_tests;
#[cfg(all(test, target_os = "macos"))]
mod qualification_admission_tests;
#[cfg(all(test, target_os = "macos"))]
mod tests;

/// Selects an authenticated initial transcript. No recovery-to-intent fallback.
/// Channel I/O never holds the session lock.
pub(super) fn run(
    channel: &mut ProtectedActivationChannel,
    enrollment: &mut DaemonProtectedCredentialEnrollmentSession,
    live: &LiveEnrollmentSession,
    sessions: &Mutex<LocalSessionService>,
    request: Zeroizing<Vec<u8>>,
) -> Result<(), LaunchAuthorityError> {
    let now = runtime::unix_now_millis()?;
    let (kind, admission) = live.with_current(sessions, || {
        enrollment
            .accept_initial_request(&request, now)
            .map_err(runtime::map_enrollment_error)
    })?;
    channel.write_control_frame(&admission)?;
    let begin = channel.read_control_frame()?;
    if kind == InitialCredentialExchange::Recovery {
        return live.with_current(sessions, || {
            enrollment
                .accept_cleanup_recovery(&begin, runtime::unix_now_millis()? / 1000)
                .map_err(runtime::map_enrollment_error)
        });
    }
    let snapshot = live.with_current(sessions, || {
        enrollment
            .begin(&begin, runtime::unix_now_millis()?)
            .map_err(runtime::map_enrollment_error)
    })?;
    channel.write_control_frame(&snapshot)
}

#[cfg(target_os = "macos")]
pub(super) enum InitialQualificationFrame {
    Legacy(Zeroizing<Vec<u8>>),
    Verified(runne_platform_desktop::VerifiedQualificationAdmission),
}

#[cfg(target_os = "macos")]
pub(super) fn read_admitted_initial_request(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    _enrollment: &mut super::runtime::V3EnrollmentDispatch,
    ticket_clock: &super::TicketClock,
) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
    #[cfg(test)]
    if let Some(observed) = _enrollment.qualification_verified.as_ref() {
        let _ = observed.compare_exchange(
            0,
            1,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
    let mut verifier = {
        #[cfg(test)]
        {
            _enrollment.qualification_verifier.take().unwrap_or_else(
                runne_native_qualification::QualificationAdmissionVerifier::from_compiled_policy,
            )
        }
        #[cfg(not(test))]
        {
            runne_native_qualification::QualificationAdmissionVerifier::from_compiled_policy()
        }
    };
    match read_initial_qualification(
        channel,
        keys,
        owned,
        installed,
        &mut verifier,
        ticket_clock()? / 1_000,
    )? {
        InitialQualificationFrame::Legacy(frame) => Ok(frame),
        InitialQualificationFrame::Verified(_verified) => {
            #[cfg(test)]
            if let Some(observed) = _enrollment.qualification_verified.as_ref() {
                let _ = observed.compare_exchange(
                    1,
                    2,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                );
            }
            Err(LaunchAuthorityError::OwnershipMismatch)
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn read_initial_qualification(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: &runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
    verifier: &mut QualificationAdmissionVerifier,
    now_unix_seconds: u64,
) -> Result<InitialQualificationFrame, LaunchAuthorityError> {
    let context_frame = channel.read_control_frame()?;
    if QualificationFaultRelayCodecV1::recognizes_frame(&context_frame) {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    if !QualificationRunContextRelayCodecV1::recognizes_frame(&context_frame) {
        return Ok(InitialQualificationFrame::Legacy(context_frame));
    }
    let fault_frame = channel.read_control_frame()?;
    if !QualificationFaultRelayCodecV1::recognizes_frame(&fault_frame) {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let release = *owned.enrollment_binding().release_tuple_digest();
    let context_binding = QualificationRunContextRelayBindingV1::new(
        *owned.session_id(),
        release,
        owned.launch_generation(),
        QualificationRunContextRelayDirectionV1::DesktopToRuntime,
        1,
    )?;
    let fault_binding = QualificationFaultRelayBindingV1::new(
        *owned.session_id(),
        release,
        owned.launch_generation(),
        QualificationFaultRelayDirectionV1::DesktopToRuntime,
        1,
    )?;
    let mut transcript = Vec::with_capacity(context_frame.len() + fault_frame.len());
    transcript.extend_from_slice(&context_frame);
    transcript.extend_from_slice(&fault_frame);
    let admission = QualificationAdmissionRelayCodecV1::from_protected_activation(keys)
        .decode_transcript(&transcript, &context_binding, &fault_binding)
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    installed
        .verify_qualification_admission(owned, verifier, admission, now_unix_seconds)
        .map(InitialQualificationFrame::Verified)
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
}
