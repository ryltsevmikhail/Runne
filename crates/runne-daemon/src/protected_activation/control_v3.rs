use super::*;

/// Serves only enrollment V3 renewal and shutdown frames.
///
/// Root-handle frames have no V3 owned-launch projection, so this loop rejects
/// them until a separately verified V3 root-admission protocol exists.
#[cfg_attr(not(test), expect(dead_code))]
pub(crate) fn run_control_loop_v3(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    let mut last_renew_sequence = 0_u64;
    loop {
        let frame = channel.read_control_frame()?;
        if let Ok(renewal) = ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&frame) {
            renewal.verify_exact(&owned_launch, last_renew_sequence, &keys)?;
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
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, *bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedCredentialEnrollmentRenewTicketV3::new(
                &renewal,
                next_session_id,
                *bootstrap_ticket,
                u64::try_from(issued_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
                u64::try_from(expires_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
            )?;
            bootstrap_ticket.zeroize();
            ticket.sign(&keys);
            let next_owned_launch = ticket
                .verify_exact_at(
                    &renewal,
                    u64::try_from(issued_at.as_millis())
                        .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
                    &keys,
                )?
                .next_owned_launch();
            let ticket_frame = Zeroizing::new(
                ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            channel.write_control_frame(&ticket_frame)?;
            last_renew_sequence = renewal.sequence();
            owned_launch = next_owned_launch;
            continue;
        }
        let shutdown = ProtectedCredentialEnrollmentShutdownV3::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(&owned_launch, &keys)?;
        let mut acknowledgement =
            ProtectedCredentialEnrollmentShutdownAckV3::new(owned_launch.clone(), true);
        acknowledgement.sign(&keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}
