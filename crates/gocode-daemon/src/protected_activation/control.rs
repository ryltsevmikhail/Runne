use super::*;

/// Serves authenticated session renewal and exact-owned shutdown requests.
///
/// Any malformed, replayed, mismatched, or disconnected control exchange
/// terminates the loop fail-closed. The caller uses loop completion as the
/// daemon application's graceful-shutdown signal.
#[cfg(unix)]
pub(crate) fn run_control_loop(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedOwnedLaunchV1,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    #[cfg(feature = "desktop-protected")] root_admission: Option<Arc<ProtectedRootControl>>,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    let mut last_renew_sequence = 0_u64;
    #[cfg(all(unix, feature = "desktop-protected"))]
    let mut last_root_sequence = 0_u64;
    #[cfg(all(unix, feature = "desktop-protected"))]
    let mut used_root_transfers = std::collections::VecDeque::new();
    loop {
        let frame = channel.read_control_frame()?;
        #[cfg(all(unix, feature = "desktop-protected"))]
        if let Some(sequence) = dispatch_root_handle_control_frame(
            &mut channel,
            &frame,
            &keys,
            &owned_launch,
            &mut used_root_transfers,
            last_root_sequence,
            unix_millis()?,
            root_admission.as_deref(),
        )? {
            last_root_sequence = sequence;
            continue;
        }
        if let Ok(renewal) = ProtectedRenewRequestV1::decode_frame(&frame) {
            renewal.verify_exact(&owned_launch, last_renew_sequence, &keys)?;
            #[cfg(feature = "desktop-protected")]
            if let Some(authority) = &root_admission {
                authority
                    .fence()
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            }

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
            let mut bootstrap_ticket = random_control_secret();
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
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;

            let issued_at_millis = u64::try_from(issued_at.as_millis())
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let expires_at_millis = u64::try_from(expires_at.as_millis())
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedRenewTicketV1::new(
                &renewal,
                next_session_id,
                bootstrap_ticket,
                issued_at_millis,
                expires_at_millis,
            )?;
            bootstrap_ticket.zeroize();
            ticket.sign(&keys);
            let ticket_frame = Zeroizing::new(
                ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            channel.write_control_frame(&ticket_frame)?;
            last_renew_sequence = renewal.sequence();
            owned_launch = ticket.next_owned_launch();
            continue;
        }

        let shutdown = ProtectedShutdownV1::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(&owned_launch, &keys)?;
        let mut acknowledgement = ProtectedShutdownAckV1::new(owned_launch.clone(), true);
        acknowledgement.sign(&keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}

/// Serves V2 control messages and rejects every V1 frame rather than allowing
/// a provider-bound launch to downgrade its authenticated transcript.
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) fn run_control_loop_v2(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedOwnedLaunchV2,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    #[cfg(feature = "desktop-protected")] root_admission: Option<Arc<ProtectedRootControl>>,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    let mut last_renew_sequence = 0_u64;
    #[cfg(all(unix, feature = "desktop-protected"))]
    let mut last_root_sequence = 0_u64;
    #[cfg(all(unix, feature = "desktop-protected"))]
    let mut used_root_transfers = std::collections::VecDeque::new();
    loop {
        let frame = channel.read_control_frame()?;
        #[cfg(all(unix, feature = "desktop-protected"))]
        if let Some(sequence) = dispatch_root_handle_control_frame(
            &mut channel,
            &frame,
            &keys,
            owned_launch.compatibility_owned_launch(),
            &mut used_root_transfers,
            last_root_sequence,
            unix_millis()?,
            root_admission.as_deref(),
        )? {
            last_root_sequence = sequence;
            continue;
        }
        if let Ok(renewal) = ProtectedRenewRequestV2::decode_frame(&frame) {
            renewal.verify_exact(&owned_launch, last_renew_sequence, &keys)?;
            #[cfg(feature = "desktop-protected")]
            if let Some(authority) = &root_admission {
                authority
                    .fence()
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            }
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
            let mut bootstrap_ticket = random_control_secret();
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
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedRenewTicketV2::new(
                &renewal,
                next_session_id,
                bootstrap_ticket,
                u64::try_from(issued_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
                u64::try_from(expires_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
            )?;
            bootstrap_ticket.zeroize();
            ticket.sign(&keys);
            channel.write_control_frame(
                &ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            )?;
            last_renew_sequence = renewal.sequence();
            owned_launch = ticket.next_owned_launch();
            continue;
        }
        let shutdown = ProtectedShutdownV2::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(&owned_launch, &keys)?;
        let mut acknowledgement = ProtectedShutdownAckV2::new(owned_launch.clone(), true);
        acknowledgement.sign(&keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
fn unix_millis() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}
