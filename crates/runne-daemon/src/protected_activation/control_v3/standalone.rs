use super::*;

#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "standalone V3 entry awaits a launch-path consumer"
    )
)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn run_control_loop_v3(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: TicketClock,
    #[cfg(unix)]
    rendezvous: super::super::enrollment_control_transition::DaemonEnrollmentRendezvous,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    super::run_control_loop_v3_entered(
        channel,
        keys,
        owned_launch,
        local_session_service,
        session_clock,
        ticket_clock,
        #[cfg(unix)]
        V3EnrollmentDispatch::new(
            None,
            rendezvous,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            None,
        ),
        None,
    )
}
