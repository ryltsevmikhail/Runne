use super::*;

#[cfg(unix)]
mod runtime;
#[cfg(unix)]
use runtime::V3EnrollmentRuntime;
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
        let installed_facts = enrollment
            .installed_facts
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let owned_rendezvous = enrollment.rendezvous.into_owned()?;
        let mut enrollment = control
            .start_protected_session(&keys, &owned_launch, owned_rendezvous, installed_facts)
            .map_err(map_enrollment_error)?;
        let request = channel.read_control_frame()?;
        let now = unix_now_millis()?;
        let admission = enrollment
            .accept_request(&request, now)
            .map_err(map_enrollment_error)?;
        channel.write_control_frame(&admission)?;
        let begin = channel.read_control_frame()?;
        let snapshot = enrollment
            .begin(&begin, unix_now_millis()?)
            .map_err(map_enrollment_error)?;
        channel.write_control_frame(&snapshot)?;
        let handoff = enrollment
            .take_bound_broker_handoff()
            .map_err(map_enrollment_error)?;
        let broker = super::broker_handoff::BrokerHandoffDispatch::from_bound_enrollment(
            &keys,
            &owned_launch,
            handoff,
        )?;
        V3EnrollmentRuntime {
            broker,
            session: Some(enrollment),
            terminal: false,
            claim_measurements: None,
            #[cfg(target_os = "macos")]
            channel: None,
        }
    } else {
        V3EnrollmentRuntime {
            broker: super::broker_handoff::BrokerHandoffDispatch::new(
                &keys,
                &owned_launch,
                enrollment.rendezvous,
            )?,
            session: None,
            terminal: true,
            claim_measurements: None,
            #[cfg(target_os = "macos")]
            channel: None,
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

fn map_enrollment_error(
    error: runne_api::ProviderCredentialEnrollmentHostError,
) -> LaunchAuthorityError {
    match error {
        runne_api::ProviderCredentialEnrollmentHostError::Unsupported => {
            LaunchAuthorityError::UnsupportedPlatformBackend
        }
        runne_api::ProviderCredentialEnrollmentHostError::Unavailable => {
            LaunchAuthorityError::ProtectedChannelUnavailable
        }
        _ => LaunchAuthorityError::OwnershipMismatch,
    }
}

fn unix_now_millis() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
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
        let frame = channel.read_control_frame()?;
        #[cfg(unix)]
        if runtime.broker.dispatch(channel, &frame, ticket_clock)? {
            #[cfg(target_os = "macos")]
            if runtime.claim_measurements.is_none()
                && let (Some(session), Some(writer)) = (
                    runtime.session.as_ref(),
                    runtime.broker.verified_writer_facts(),
                )
            {
                let launch_attempt = runtime
                    .broker
                    .verified_writer_launch_attempt()
                    .ok_or(LaunchAuthorityError::InvalidContract)?;
                runtime.claim_measurements = Some(
                    session
                        .prepare_claim_measurements(writer, launch_attempt)
                        .map_err(map_enrollment_error)?,
                );
            }
            #[cfg(target_os = "macos")]
            runtime.drive_claimed_writer(channel)?;
            continue;
        }
        if let Ok(renewal) = ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&frame) {
            #[cfg(unix)]
            if !enrollment_transcript_allows_rotation(runtime.session.is_some(), runtime.terminal) {
                return Err(LaunchAuthorityError::OwnershipMismatch);
            }
            renewal.verify_exact(owned_launch, last_renew_sequence, keys)?;
            let current = local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .current_binding()
                .clone();
            let mut next_session_id = *uuid::Uuid::now_v7().as_bytes();
            while next_session_id == *current.ephemeral().session_id()
                || next_session_id == current.ephemeral().daemon_instance_id().into_bytes()
            {
                next_session_id = *uuid::Uuid::now_v7().as_bytes();
            }
            let mut bootstrap_ticket = Zeroizing::new(random_control_secret());
            let issued_at = session_clock();
            let expires_at = issued_at
                .checked_add(Duration::from_secs(30))
                .ok_or(LaunchAuthorityError::RenewalUnavailable)?;
            let next_binding = RuntimeSessionBinding::new(
                current.stable().clone(),
                current.ephemeral().daemon_instance_id(),
                current.ephemeral().launch_generation(),
                next_session_id,
                current.ephemeral().authorization_epoch(),
                current.ephemeral().sensitivity_ceiling(),
                *current.certificate_sha256(),
            )
            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let ticket_issued_at = ticket_clock()?;
            let ticket_expires_at = ticket_issued_at
                .checked_add(30_000)
                .ok_or(LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
                &renewal,
                next_session_id,
                *bootstrap_ticket,
                ticket_issued_at,
                ticket_expires_at,
            )?;
            ticket.sign(keys);
            let next_owned_launch = ticket
                .verify_exact_at(&renewal, ticket_issued_at, keys)?
                .next_owned_launch();
            let ticket_frame = Zeroizing::new(
                ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, *bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            bootstrap_ticket.zeroize();
            // A write failure returns from this loop and fences the rotated
            // service behind daemon termination; the ticket is never retried.
            channel.write_control_frame(&ticket_frame)?;
            last_renew_sequence = renewal.sequence();
            *owned_launch = next_owned_launch;
            continue;
        }
        let shutdown = ProtectedCredentialEnrollmentShutdownV3::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        #[cfg(unix)]
        if !runtime.accepts_shutdown() {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        shutdown.verify_exact(owned_launch, keys)?;
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
