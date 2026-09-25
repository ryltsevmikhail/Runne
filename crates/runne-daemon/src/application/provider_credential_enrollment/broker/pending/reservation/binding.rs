use super::*;

#[cfg(unix)]
#[derive(PartialEq, Eq)]
pub(super) struct ReservedAuthorityBinding {
    installation: [u8; 32],
    release: [u8; 32],
    protected_session: [u8; 32],
    tauri_peer: [u8; 32],
    daemon: [u8; 32],
    database_generation: u64,
    supervisor_generation: u64,
    proof: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::application::provider_credential_enrollment::broker) struct PendingBrokerRendezvousBinding
{
    pub(in crate::application::provider_credential_enrollment::broker) operation_id:
        CredentialOperationId,
    pub(in crate::application::provider_credential_enrollment::broker) begin_proof:
        CredentialBindingDigest,
    pub(in crate::application::provider_credential_enrollment::broker) owner:
        CredentialInstallationOwnerId,
    pub(in crate::application::provider_credential_enrollment::broker) protected_session: [u8; 32],
    pub(in crate::application::provider_credential_enrollment::broker) tauri_peer: [u8; 32],
    pub(in crate::application::provider_credential_enrollment::broker) daemon_authority: [u8; 32],
    pub(in crate::application::provider_credential_enrollment::broker) database_generation: u64,
    pub(in crate::application::provider_credential_enrollment::broker) supervisor_generation: u64,
    pub(in crate::application::provider_credential_enrollment::broker) release_tuple:
        CredentialBindingDigest,
    pub(in crate::application::provider_credential_enrollment::broker) expires_at_high_water: i64,
}

#[cfg(unix)]
impl ReservedAuthorityBinding {
    pub(super) fn new(
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
    ) -> Self {
        Self {
            installation: *authority.installation_identity(),
            release: *authority.release_tuple_digest(),
            protected_session: *authority.protected_session_id(),
            tauri_peer: *authority.authenticated_tauri_peer_process(),
            daemon: *authority.daemon_authority_id(),
            database_generation: authority.database_generation(),
            supervisor_generation: authority.desktop_supervisor_generation(),
            proof: *proof.proof_digest(),
        }
    }
}

impl PendingBrokerRendezvousBinding {
    #[cfg(all(
        feature = "desktop-protected",
        any(test, all(target_os = "macos", target_arch = "aarch64"))
    ))]
    // Read by the macOS projection; the accessor stays compiled everywhere.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(in crate::application::provider_credential_enrollment::broker) const fn release_tuple(
        &self,
    ) -> CredentialBindingDigest {
        self.release_tuple
    }

    // The binding is minted only from the unix broker transport (and the
    // macOS protected qualification suites); windows begin refuses earlier.
    #[cfg(all(test, unix))]
    pub(in crate::application::provider_credential_enrollment::broker) fn new(
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let binding = Self::for_handoff(operation, authority, proof, now_high_water)?;
        if operation.begin_proof_digest() != binding.begin_proof {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(binding)
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn for_handoff(
        operation: &CredentialOperationSnapshot,
        authority: &ProviderCredentialBaseRequestAuthority,
        proof: &ProviderCredentialIntentConsumptionProof,
        now_high_water: i64,
    ) -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let begin_proof = CredentialBindingDigest::from_measured(*proof.proof_digest())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let release_tuple =
            CredentialBindingDigest::from_measured(*authority.release_tuple_digest())
                .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let owner = CredentialInstallationOwnerId::from_bytes(*authority.installation_identity())
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        validate_authority(authority, proof, now_high_water)?;
        if operation.state() != CredentialOperationState::Prepared
            || operation.installation_owner_id() != owner
            || operation.metadata().qualified_release_tuple_digest() != Some(release_tuple)
        {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(Self {
            operation_id: operation.operation_id(),
            begin_proof,
            owner,
            protected_session: *authority.protected_session_id(),
            tauri_peer: *authority.authenticated_tauri_peer_process(),
            daemon_authority: *authority.daemon_authority_id(),
            database_generation: authority.database_generation(),
            supervisor_generation: authority.desktop_supervisor_generation(),
            release_tuple,
            expires_at_high_water: proof.expires_at_high_water(),
        })
    }

    pub(in crate::application::provider_credential_enrollment::broker) const fn expired(
        self,
        now_high_water: i64,
    ) -> bool {
        now_high_water >= self.expires_at_high_water
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
pub(super) fn validate_authority(
    authority: &ProviderCredentialBaseRequestAuthority,
    proof: &ProviderCredentialIntentConsumptionProof,
    now_high_water: i64,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    if now_high_water <= 0
        || proof.protected_session_binding() != authority.protected_session_id()
        || proof.expires_at_high_water() <= now_high_water
        || authority.protected_session_id() == &[0; 32]
        || authority.authenticated_tauri_peer_process() == &[0; 32]
        || authority.daemon_authority_id() == &[0; 32]
        || authority.database_generation() == 0
        || authority.desktop_supervisor_generation() == 0
    {
        return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
    }
    Ok(())
}
