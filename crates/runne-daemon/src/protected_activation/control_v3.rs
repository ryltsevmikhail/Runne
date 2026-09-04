use super::*;
#[cfg(unix)]
mod discovery;
#[cfg(unix)]
mod initial_exchange;
mod live_session;
mod renewal;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod round;
#[cfg(unix)]
mod runtime;
#[cfg(unix)]
use runtime::V3EnrollmentRuntime;
#[cfg(all(test, unix))]
pub(crate) use runtime::require_shutdown_terminal;
#[cfg(all(test, target_os = "macos"))]
pub(super) use runtime::with_control;
#[cfg(unix)]
pub(super) use runtime::{V3EnrollmentDispatch, enrollment_transcript_allows_rotation};
type TicketClock = Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;

/// Builds the production ticket clock without making an unverified V3 launch
/// path available. Non-Apple-Silicon targets fail closed when wired later.
#[allow(dead_code)]
pub(crate) fn macos_continuous_ticket_clock() -> TicketClock {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Arc::new(|| {
            runne_platform_desktop::MacOsContinuousClock::now_millis()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)
        })
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    Arc::new(|| Err(LaunchAuthorityError::RenewalUnavailable))
}

/// Serves only enrollment V3 renewal, broker writer-handoff, and shutdown
/// frames.
///
/// Enters the channel, then serves the V3 transcript. Root-handle frames have
/// no V3 owned-launch projection, so this loop rejects them until a separately
/// verified V3 root-admission protocol exists.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "standalone V3 entry awaits a launch-path consumer"
    )
)]
pub(crate) fn run_control_loop_v3(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: TicketClock,
    #[cfg(unix)] rendezvous: super::enrollment_control_transition::DaemonEnrollmentRendezvous,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    run_control_loop_v3_entered(
        channel,
        keys,
        owned_launch,
        local_session_service,
        session_clock,
        ticket_clock,
        #[cfg(unix)]
        V3EnrollmentDispatch::new(None, rendezvous, None),
    )
}

/// The V3 transcript continuation for a channel that is already entered.
///
/// The same-process enrollment transition tail-calls this variant after its
/// in-place upgrade; calling `enter_control_loop` twice would re-run the entry
/// handshake on an already-authenticated channel.
///
/// Broker handoff offers consume the transition rendezvous exactly once, in
/// fixed purpose order. Once a renewal rotates the local session, a failed
/// channel write terminates this loop; callers must terminate the daemon
/// rather than retrying on another path. After the kill-capability
/// acknowledgement the retained kill authority terminates the exact writer on
/// any later loop failure. V1/V2 frames decode as neither V3 message and fail
/// closed.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub(crate) fn run_control_loop_v3_entered(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: TicketClock,
    #[cfg(unix)] enrollment: V3EnrollmentDispatch,
) -> Result<(), LaunchAuthorityError> {
    #[cfg(unix)]
    let mut runtime = if let Some(control) = enrollment.control {
        let live =
            live_session::LiveEnrollmentSession::capture(&local_session_service, &owned_launch)?;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let round = enrollment.round_profile.map(|profile| round::RoundContext {
            profile,
            control: Arc::clone(&control),
            previous: owned_launch.clone(),
        });
        let installed_facts = enrollment
            .installed_facts
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        #[cfg(target_os = "macos")]
        let credential_service_configuration =
            installed_facts.runtime_credential_service_configuration();
        #[cfg(target_os = "macos")]
        let credential_service_session =
            super::credential_service_registration::receive_required_registration(
                &mut channel,
                &keys,
                &owned_launch,
                &installed_facts,
                runtime::unix_now_millis()?,
            )?;
        #[cfg(target_os = "macos")]
        let credential_service = credential_service_session
            .map(|session| control.install_credential_service_session(session))
            .transpose()
            .map_err(runtime::map_enrollment_error)?;
        let owned_rendezvous = enrollment.rendezvous.into_owned()?;
        let mut enrollment = control
            .start_protected_session(&keys, &owned_launch, owned_rendezvous, installed_facts)
            .map_err(runtime::map_enrollment_error)?;
        initial_exchange::run(&mut channel, &mut enrollment, &live, &local_session_service)?;
        let terminal = enrollment.begun_is_terminal();
        let broker = runtime::bind_broker(&keys, &owned_launch, &mut enrollment)?;
        V3EnrollmentRuntime {
            #[cfg(target_os = "macos")]
            deferred_control: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            round,
            live: Some(live),
            broker,
            session: Some(enrollment),
            terminal,
            claim_measurements: None,
            #[cfg(target_os = "macos")]
            channel: None,
            #[cfg(target_os = "macos")]
            credential_service,
            #[cfg(target_os = "macos")]
            credential_service_configuration,
        }
    } else {
        V3EnrollmentRuntime {
            #[cfg(target_os = "macos")]
            deferred_control: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            round: None,
            live: None,
            broker: Some(super::broker_handoff::BrokerHandoffDispatch::new(
                &keys,
                &owned_launch,
                enrollment.rendezvous,
            )?),
            session: None,
            terminal: true,
            claim_measurements: None,
            #[cfg(target_os = "macos")]
            channel: None,
            #[cfg(target_os = "macos")]
            credential_service: None,
            #[cfg(target_os = "macos")]
            credential_service_configuration: None,
        }
    };
    let transcript = serve_v3_transcript(
        &mut channel,
        &keys,
        &mut owned_launch,
        &local_session_service,
        &session_clock,
        &ticket_clock,
        #[cfg(unix)]
        &mut runtime,
    );
    #[cfg(all(unix, target_os = "macos"))]
    if transcript.is_err() {
        // Fail-closed recovery: the exact writer never outlives a failed loop.
        runtime.terminate_retained_writer();
    }
    transcript
}

#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
#[allow(clippy::too_many_arguments)]
fn serve_v3_transcript(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned_launch: &mut ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: &TicketClock,
    #[cfg(unix)] runtime: &mut V3EnrollmentRuntime,
) -> Result<(), LaunchAuthorityError> {
    let mut last_renew_sequence = 0_u64;
    loop {
        #[cfg(target_os = "macos")]
        if runtime.yield_for_credential_service_rejoin(channel, keys, owned_launch)? {
            continue;
        }
        #[cfg(target_os = "macos")]
        let frame = match runtime.deferred_control.take() {
            Some(frame) => frame,
            None => channel.read_control_frame()?,
        };
        #[cfg(not(target_os = "macos"))]
        let frame = channel.read_control_frame()?;
        #[cfg(unix)]
        if runne_api::ProtectedCredentialDiscoveryCodec::recognizes_frame(&frame) {
            runtime.discover_cleanup(channel, keys, owned_launch, local_session_service, &frame)?;
            continue;
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if runne_api::ProtectedCredentialRoundCodec::recognizes_frame(&frame) {
            runtime.begin_next_round(channel, keys, owned_launch, local_session_service, &frame)?;
            continue;
        }
        #[cfg(unix)]
        if let Some(broker) = runtime.broker.as_mut()
            && broker.dispatch(channel, &frame, ticket_clock)?
        {
            #[cfg(target_os = "macos")]
            if runtime.claim_measurements.is_none()
                && let (Some(session), Some(writer)) =
                    (runtime.session.as_ref(), broker.verified_writer_facts())
            {
                let launch_attempt = broker
                    .verified_writer_launch_attempt()
                    .ok_or(LaunchAuthorityError::InvalidContract)?;
                runtime.claim_measurements = Some(
                    session
                        .prepare_claim_measurements(writer, launch_attempt)
                        .map_err(runtime::map_enrollment_error)?,
                );
            }
            #[cfg(target_os = "macos")]
            runtime.drive_claimed_writer(channel, local_session_service, keys, owned_launch)?;
            continue;
        }
        if let Ok(renewal) = ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&frame) {
            #[cfg(unix)]
            if !enrollment_transcript_allows_rotation(runtime.session.is_some(), runtime.terminal) {
                return Err(LaunchAuthorityError::OwnershipMismatch);
            }
            #[cfg(unix)]
            if let Some(session) = runtime.session.as_ref() {
                session
                    .require_durable_terminal()
                    .map_err(runtime::map_enrollment_error)?;
            }
            let next_owned_launch = renewal::rotate(
                channel,
                keys,
                owned_launch,
                local_session_service,
                session_clock,
                ticket_clock,
                &renewal,
                last_renew_sequence,
            )?;
            last_renew_sequence = renewal.sequence();
            *owned_launch = next_owned_launch;
            continue;
        }
        let shutdown = ProtectedCredentialEnrollmentShutdownV3::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(owned_launch, keys)?;
        #[cfg(unix)]
        runtime.require_shutdown()?;
        let mut acknowledgement =
            ProtectedCredentialEnrollmentShutdownAckV3::new(owned_launch.clone(), true);
        acknowledgement.sign(keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}
