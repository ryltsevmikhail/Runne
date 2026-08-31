#![cfg(test)]

use std::sync::Arc;

use runne_provider::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialNativeCreateClaim,
    CredentialVersionRef, NativeCredentialAuthority, NativeCredentialDeletionProof,
};
use runne_secure_store::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, ProviderCredentialStatus, SecureStoreError,
};

use crate::application::workspace_internal::FixtureCredentialVersionStoreFactory;

struct LoopbackCredentialVersionStore {
    authority: NativeCredentialAuthority,
}

impl NativeProviderCredentialVersionStore for LoopbackCredentialVersionStore {
    fn version_status(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(ProviderCredentialStatus::Configured)
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn load_version(
        &self,
        _capability: &CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        self.authority
            .authorize_delete(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        self.authority
            .prove_deletion(claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }
}

pub(super) fn factory() -> Arc<FixtureCredentialVersionStoreFactory> {
    Arc::new(|authority| Arc::new(LoopbackCredentialVersionStore { authority }))
}
