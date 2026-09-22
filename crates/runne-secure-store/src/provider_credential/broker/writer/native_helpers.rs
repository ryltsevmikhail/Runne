use crate::{ProviderCredentialId, SecureStoreError};
use runne_provider::{
    CredentialLifecycleError, CredentialNativeCreateValidator, CredentialVersionRef, ProviderId,
};

pub(super) struct BrokerAuthorizedCreate;

impl CredentialNativeCreateValidator for BrokerAuthorizedCreate {
    fn validate(&self) -> Result<(), CredentialLifecycleError> {
        Ok(())
    }
}

pub(super) fn version(
    target: &runne_provider::CredentialBrokerTarget,
) -> Result<&CredentialVersionRef, SecureStoreError> {
    target
        .version_ref()
        .ok_or(SecureStoreError::CredentialAccessDenied)
}

pub(super) fn provider(provider: &ProviderId) -> Result<ProviderCredentialId, SecureStoreError> {
    ProviderCredentialId::from_account(provider.as_str())
        .ok_or(SecureStoreError::UnsupportedSecureStoreBackend)
}

pub(super) const fn map_lifecycle(error: CredentialLifecycleError) -> SecureStoreError {
    match error {
        CredentialLifecycleError::StaleLease | CredentialLifecycleError::Conflict => {
            SecureStoreError::CredentialAccessDenied
        }
        CredentialLifecycleError::CorruptState => SecureStoreError::CorruptProviderCredential,
        _ => SecureStoreError::ProviderCredentialOperationFailed,
    }
}
