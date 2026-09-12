use super::*;

pub(super) fn with_current<T>(
    sessions: &Mutex<LocalSessionService>,
    owned: &ProtectedOwnedLaunchV2,
    read: impl FnOnce() -> Result<T, LaunchAuthorityError>,
) -> Result<T, LaunchAuthorityError> {
    let service = sessions
        .lock()
        .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?;
    let binding = service.current_binding();
    let stable = binding.stable();
    let expected = owned.compatibility_owned_launch().stable();
    let ephemeral = binding.ephemeral();
    if ephemeral.session_id() != owned.session_id()
        || ephemeral.daemon_instance_id().as_bytes() != owned.daemon_instance_id()
        || ephemeral.launch_generation() != owned.launch_generation()
        || stable.authority_id() != expected.authority_id()
        || stable.principal_id().as_str() != expected.principal_id()
        || stable.lineage_id().as_bytes() != expected.lineage_id()
        || stable.profile_id() != expected.profile_id()
        || stable.schema_hash() != expected.profile_hash()
        || stable.capability_digest() != expected.capability_digest()
    {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let result = read();
    drop(service);
    result
}

pub(super) fn respond(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV2,
    sessions: &Mutex<LocalSessionService>,
    composition: Option<&(
        enrollment_control_transition::EnrollmentControlComposition,
        installation_anchor::VerifiedNativeEnrollmentInstallation,
    )>,
    frame: &[u8],
) -> Result<(), LaunchAuthorityError> {
    let (composition, installation) = composition.ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    if &composition.installation_identity_digest != installation.installation_identity_digest() {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let control = composition
        .enrollment_control
        .as_ref()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    let mut codec = runne_api::ProtectedCredentialDiscoveryCodec::for_startup(keys, owned);
    codec.decode_request(frame)?;
    let ids = with_current(sessions, owned, || {
        control
            .discover_cleanup_for_owner(*installation.installation_identity_digest())
            .map_err(|_| LaunchAuthorityError::OwnershipMismatch)
    })?;
    channel.write_control_frame(&codec.encode_response(&ids)?)
}

#[cfg(test)]
mod tests;
