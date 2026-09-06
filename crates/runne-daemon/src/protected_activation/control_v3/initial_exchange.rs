use super::{live_session::LiveEnrollmentSession, runtime};
use crate::application::provider_credential_enrollment::{
    DaemonProtectedCredentialEnrollmentSession, InitialCredentialExchange,
};
use crate::protected_activation::ProtectedActivationChannel;
use runne_api::{
    LaunchAuthorityError, ProtectedActivationKeys, ProtectedCredentialEnrollmentOwnedLaunchV3,
};
#[cfg(target_os = "macos")]
use runne_api::{QualificationFaultRelayBindingV1, QualificationFaultRelayDirectionV1};
use runne_application::local_session::LocalSessionService;
#[cfg(target_os = "macos")]
use runne_native_qualification::QualificationFaultRelayCodecV1;
use std::sync::Mutex;
use zeroize::Zeroizing;

#[cfg(all(test, target_os = "macos"))]
mod tests;

/// Selects an authenticated initial transcript. No recovery-to-intent fallback.
/// Channel I/O never holds the session lock.
pub(super) fn run(
    channel: &mut ProtectedActivationChannel,
    enrollment: &mut DaemonProtectedCredentialEnrollmentSession,
    live: &LiveEnrollmentSession,
    sessions: &Mutex<LocalSessionService>,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> Result<(), LaunchAuthorityError> {
    let request = read_initial_request(channel, keys, owned)?;
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

fn read_initial_request(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
    let frame = channel.read_control_frame()?;
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (keys, owned);
        return Ok(frame);
    }
    #[cfg(target_os = "macos")]
    {
        if !QualificationFaultRelayCodecV1::recognizes_frame(&frame) {
            return Ok(frame);
        }
        let binding = QualificationFaultRelayBindingV1::new(
            *owned.session_id(),
            *owned.enrollment_binding().release_tuple_digest(),
            owned.launch_generation(),
            QualificationFaultRelayDirectionV1::DesktopToRuntime,
            1,
        )?;
        let codec = QualificationFaultRelayCodecV1::from_protected_activation(keys);
        let payload = frame
            .get(4..)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let _pending = codec
            .decode(payload, &binding)
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        Err(LaunchAuthorityError::OwnershipMismatch)
    }
}
