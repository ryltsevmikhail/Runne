// Linux local-runtime production exchange. Split from
// `enrollment_control_transition.rs` to honor the 300-line source limit;
// included at the end of the same module scope.

/// Linux local-runtime production exchange: the ownership proof is the signed
/// V2 transcript plus the kernel peer credential of the desktop supervisor
/// (same-uid) measured against the claims; the macOS codesign/qualification
/// admission has no Linux equivalent and is not simulated.
#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[allow(clippy::too_many_arguments)] // The exact transcript tuple stays explicit.
pub(crate) fn run_enrollment_control_exchange(
    channel: &mut ProtectedActivationChannel,
    prepare: &ProtectedCredentialEnrollmentPrepareV2,
    keys: &ProtectedActivationKeys,
    owned: &runne_api::ProtectedOwnedLaunchV2,
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
