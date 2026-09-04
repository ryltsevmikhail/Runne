use super::*;
use crate::application::provider_credential_enrollment::effect_authority::map_store;
use runne_provider::{
    CredentialInstallationOwnerId, ProviderCredentialEnrollmentStore, ProviderId,
};

impl DaemonProtectedCredentialEnrollmentSession {
    /// Caller holds the exact live-session guard. Metadata only, no admission.
    pub(crate) fn discover_cleanup(
        &self,
    ) -> Result<Vec<[u8; 16]>, ProviderCredentialEnrollmentHostError> {
        self.control
            .discover_cleanup_for_owner(self.facts.installation)
    }
}

impl DaemonProviderCredentialEnrollmentControl {
    /// Internal metadata read; caller derives owner from verified installation.
    pub(crate) fn discover_cleanup_for_owner(
        &self,
        installation: [u8; 32],
    ) -> Result<Vec<[u8; 16]>, ProviderCredentialEnrollmentHostError> {
        let owner = CredentialInstallationOwnerId::from_bytes(installation)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        let mut ids = Vec::new();
        for provider in ["openai", "deepseek"] {
            let provider = ProviderId::new(provider)
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?;
            for operation in self
                .store
                .prepared_cleanup_operations(owner, &provider)
                .map_err(map_store)?
            {
                ids.push(operation.operation_id().as_bytes());
            }
            if ids.len() > 64 {
                return Err(ProviderCredentialEnrollmentHostError::InvariantViolation);
            }
        }
        Ok(ids)
    }
}
