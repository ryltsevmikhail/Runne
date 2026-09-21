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
    run_enrollment_control_exchange_with(
        channel,
        prepare,
        keys,
        owned,
        composition,
        sessions,
        session_clock,
        |_, claims, stream| runne_platform_desktop::verify_linux_enrollment_peer(stream, claims),
        |input, request, channel| {
            transition_with(
                input,
                request,
                |stream, claims| {
                    runne_platform_desktop::verify_linux_enrollment_peer(stream, claims)
                },
                channel,
            )
        },
    )
}
