use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn rotate(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned_launch: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: &TicketClock,
    renewal: &ProtectedCredentialEnrollmentRenewRequestV3,
    last_renew_sequence: u64,
) -> Result<ProtectedCredentialEnrollmentOwnedLaunchV3, LaunchAuthorityError> {
    renewal.verify_exact(owned_launch, last_renew_sequence, keys)?;
    let current =
        live_session::LiveEnrollmentSession::capture(local_session_service, owned_launch)?
            .into_binding();
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
        renewal,
        next_session_id,
        *bootstrap_ticket,
        ticket_issued_at,
        ticket_expires_at,
    )?;
    ticket.sign(keys);
    let next_owned_launch = ticket
        .verify_exact_at(renewal, ticket_issued_at, keys)?
        .next_owned_launch();
    let ticket_frame = Zeroizing::new(
        ticket
            .encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    );
    let mut service = local_session_service
        .lock()
        .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
    if service.current_binding() != &current {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    service
        .rotate_protected_bootstrap(next_binding, *bootstrap_ticket, issued_at, expires_at)
        .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
    drop(service);
    bootstrap_ticket.zeroize();
    // A write failure returns from this loop and fences the rotated
    // service behind daemon termination; the ticket is never retried.
    channel.write_control_frame(&ticket_frame)?;
    Ok(next_owned_launch)
}

#[cfg(test)]
mod tests;
