use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn respond(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV2,
    sessions: &std::sync::Mutex<runne_application::local_session::LocalSessionService>,
    composition: &enrollment_control_transition::EnrollmentControlComposition,
    frame: &[u8],
    last_sequence: u64,
) -> Result<u64, LaunchAuthorityError> {
    let request = runne_api::ProtectedCredentialStatusRequestV2::decode_frame(frame)
        .map_err(|_| LaunchAuthorityError::InvalidContract)?;
    let verified = request.verify_exact_view(owned, last_sequence, keys)?;
    super::startup_discovery::with_current(sessions, owned, || Ok(()))?;
    let claims = verified.prepare_claims();
    if composition.enrollment_control.is_none() && composition.enrollment_controls.is_empty() {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let native =
        runne_platform_desktop::VerifiedDaemonNativeEnrollmentPrepare::verify_current_for_peer(
            &composition.profile_directory,
            &composition.runtime_root,
            claims,
            channel.unix_stream(),
        )
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    let installed = native
        .revalidate_and_measure_current_peer_for_claims(channel.unix_stream(), claims)
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    if installed.release() != *claims.release_tuple_digest()
        || installed.qualification() != *claims.qualification_binding_digest()
    {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    super::startup_discovery::with_current(sessions, owned, || {
        composition
            .publish_verified_v2_status(
                owned,
                installed.release(),
                *claims.desktop_peer_binding_digest(),
                claims.desktop_supervisor_generation(),
            )
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    })?;
    let native = runne_api::ProtectedCredentialStatusNativeClaimsV2::new(
        composition.installation_identity_digest,
        installed.release(),
        installed.qualification(),
        *claims.desktop_peer_binding_digest(),
        claims.desktop_supervisor_generation(),
        installed.installed_generation(),
    )?;
    let mut ack = runne_api::ProtectedCredentialStatusAckV2::new(&verified, native)?;
    ack.sign(keys);
    channel.write_control_frame(
        &ack.encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    )?;
    Ok(request.sequence())
}
