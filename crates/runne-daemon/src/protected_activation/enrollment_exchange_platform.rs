// Platform composition of the production enrollment exchange.
//
// Both native admission steps authenticate the exact live peer; only the
// evidence differs per platform. Split out of `enrollment_control_transition`
// to keep every source file under the 300-line limit.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_api::{
    LaunchAuthorityError, ProtectedActivationKeys, ProtectedCredentialEnrollmentPrepareV2,
    ProtectedOwnedLaunchV2,
};
use runne_application::local_session::LocalSessionService;

use super::ProtectedActivationChannel;
use super::enrollment_control_transition::{
    EnrollmentControlComposition, EnrollmentTransitionOutcome,
};

/// macOS production exchange: both native admission steps authenticate the
/// exact live kernel peer against journals, identities, and the V2 claims,
/// and the V3 launch is admitted through `admit_v2_to_v3_transition` with the
/// exact retained installation anchor.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_enrollment_control_exchange(
    channel: &mut ProtectedActivationChannel,
    prepare: &ProtectedCredentialEnrollmentPrepareV2,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV2,
    composition: &EnrollmentControlComposition,
    sessions: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    installation: &super::installation_anchor::VerifiedNativeEnrollmentInstallation,
) -> Result<EnrollmentTransitionOutcome, LaunchAuthorityError> {
    use std::cell::RefCell;

    use super::enrollment_control_exchange::run_enrollment_control_exchange_with;
    use super::enrollment_transition_v2_v3::admit_v2_to_v3_transition;

    let native: RefCell<Option<runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare>> =
        RefCell::new(None);
    run_enrollment_control_exchange_with(
        channel,
        prepare,
        keys,
        owned,
        composition,
        sessions,
        session_clock,
        |profile_directory, claims, stream| {
            *native.borrow_mut() = runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare::verify_current_for_peer(
                profile_directory,
                &composition.runtime_root,
                claims,
                stream,
            );
            native.borrow().is_some()
        },
        |input, request, channel| {
            let Some(native) = native.borrow_mut().take() else {
                return Err(LaunchAuthorityError::OwnershipMismatch);
            };
            admit_v2_to_v3_transition(input, installation, native, channel, request)
        },
    )
}

/// Linux local-runtime production exchange: the ownership proof is the signed
/// V2 transcript plus the kernel peer credential of the desktop supervisor
/// (same-uid) measured against the claims; the macOS codesign/qualification
/// admission has no Linux equivalent and is not simulated.
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_enrollment_control_exchange(
    channel: &mut ProtectedActivationChannel,
    prepare: &ProtectedCredentialEnrollmentPrepareV2,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV2,
    composition: &EnrollmentControlComposition,
    sessions: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    installation: &super::installation_anchor::VerifiedNativeEnrollmentInstallation,
) -> Result<EnrollmentTransitionOutcome, LaunchAuthorityError> {
    use super::enrollment_control_exchange::run_enrollment_control_exchange_with;
    use super::enrollment_transition_v2_v3::transition_with;

    let _ = installation;
    let measured = std::cell::RefCell::new(None);
    let writer_capability = std::cell::RefCell::new(None);
    let outcome = run_enrollment_control_exchange_with(
        channel,
        prepare,
        keys,
        owned,
        composition,
        sessions,
        session_clock,
        |profile_directory, claims, stream| {
            let Some(resource_directory_hint) = claims.resource_directory_hint() else {
                #[cfg(feature = "linux-native-enrollment-qualification")]
                runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("resource_hint_missing");
                return false;
            };
            #[cfg(feature = "linux-native-enrollment-qualification")]
            runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("writer_capability_begin");
            let Some(capability) =
                runne_platform_desktop::VerifiedInstalledLinuxWriterCapability::
                    load_current_for_authenticated_desktop_peer(
                        profile_directory,
                        &composition.runtime_root,
                        std::path::Path::new(resource_directory_hint),
                        stream,
                    )
            else {
                #[cfg(feature = "linux-native-enrollment-qualification")]
                runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("writer_capability_failed");
                return false;
            };
            #[cfg(feature = "linux-native-enrollment-qualification")]
            runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("writer_capability_ready");
            *writer_capability.borrow_mut() = Some(capability);
            if require_linux_transition_control(composition.enrollment_control.is_some()).is_err() {
                #[cfg(feature = "linux-native-enrollment-qualification")]
                runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("enrollment_control_missing");
                return false;
            }
            #[cfg(feature = "linux-native-enrollment-qualification")]
            runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("measurement_begin");
            *measured.borrow_mut() =
                runne_platform_desktop::measure_verified_linux_enrollment_installation(
                    stream,
                    claims,
                    &composition.runtime_root,
                    *owned.compatibility_owned_launch().stable().authority_id(),
                    *composition
                        .original_request
                        .executable()
                        .executable_sha256(),
                );
            let ready = measured.borrow().is_some();
            #[cfg(feature = "linux-native-enrollment-qualification")]
            runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage(if ready { "measurement_ready" } else { "measurement_failed" });
            ready
        },
        |input, request, channel| {
            #[cfg(feature = "linux-native-enrollment-qualification")]
            runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage("transition_begin");
            transition_with(
                input,
                request,
                |stream, claims| {
                    runne_platform_desktop::verify_linux_enrollment_peer(stream, claims)
                },
                channel,
            )
        },
    );
    #[cfg(feature = "linux-native-enrollment-qualification")]
    runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage(if outcome.is_ok() { "transition_ready" } else { "transition_failed" });
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            composition.clear_http_facts(*owned.session_id());
            return Err(error);
        }
    };
    let http_controls = composition.session_controls();
    let installed = super::enrollment_control_fanout::install_linux_preadmission(
        &http_controls,
        outcome.owned_launch(),
        &composition.runtime_root,
        measured
            .into_inner()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?,
    );
    #[cfg(feature = "linux-native-enrollment-qualification")]
    runne_platform_desktop::provider_credential_broker::linux_native_enrollment_qualification::record_enrollment_stage(if installed.is_ok() { "profile_install_ready" } else { "profile_install_failed" });
    if installed.is_err() {
        composition.clear_http_facts(*outcome.owned_launch().session_id());
    }
    installed.map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    Ok(outcome.with_linux_writer_capability(
        writer_capability
            .into_inner()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?,
    ))
}

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
fn require_linux_transition_control(has_control: bool) -> Result<(), LaunchAuthorityError> {
    if has_control {
        Ok(())
    } else {
        Err(LaunchAuthorityError::OwnershipMismatch)
    }
}

#[cfg(all(test, target_os = "linux", feature = "desktop-protected"))]
mod linux_control_tests {
    use super::require_linux_transition_control;
    use runne_api::LaunchAuthorityError;

    #[test]
    fn signed_writer_transition_fails_before_prelude_without_control() {
        assert_eq!(
            require_linux_transition_control(false),
            Err(LaunchAuthorityError::OwnershipMismatch)
        );
        assert!(require_linux_transition_control(true).is_ok());
    }
}
