use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialStatus, ProviderCredentialStore,
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStore, SecureStoreError,
};
use gocode_provider::CredentialVersionRef;
use gocode_provider::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialNativeCreateClaim,
    NativeCredentialAuthority, NativeCredentialDeletionProof,
};

/// Stub implementation for platforms where the secure store is not yet wired.
/// All operations return `Unavailable`.
#[derive(Default)]
pub struct StubStore {
    version_authority: Option<NativeCredentialAuthority>,
}

impl StubStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            version_authority: None,
        }
    }

    /// Constructs the fail-closed backend bound to a lifecycle authority.
    #[must_use]
    pub const fn new_versioned(authority: NativeCredentialAuthority) -> Self {
        Self {
            version_authority: Some(authority),
        }
    }
}

impl SecureStore for StubStore {
    fn store_anchor(&self, _generation: u64) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    fn delete_anchor(&self) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
}

impl ProviderJournalKeyring for StubStore {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        false
    }

    fn provider_journal_key_status(
        &self,
        _key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(ProviderJournalKeyStatus::Unsupported)
    }

    fn store_provider_journal_key(
        &self,
        _key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn load_provider_journal_key(
        &self,
        _key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn delete_provider_journal_key(
        &self,
        _key_ref: ProviderJournalKeyRef,
        _proof: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}

impl ProviderCredentialStore for StubStore {
    fn provider_credential_status(
        &self,
        _provider: ProviderCredentialId,
        _expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(ProviderCredentialStatus::Unsupported)
    }

    fn store_provider_credential(
        &self,
        _provider: ProviderCredentialId,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn load_provider_credential(
        &self,
        _provider: ProviderCredentialId,
        _expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn delete_provider_credential(
        &self,
        _provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn migrate_provider_credential_access(
        &self,
        _provider: ProviderCredentialId,
        _current: &ProviderCredentialAccessPolicy,
        _replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}

impl NativeProviderCredentialVersionStore for StubStore {
    fn version_status(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(ProviderCredentialStatus::Unsupported)
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.version_authority
            .as_ref()
            .ok_or(SecureStoreError::CredentialAccessDenied)?
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn load_version(
        &self,
        capability: &CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let authority = self
            .version_authority
            .as_ref()
            .ok_or(SecureStoreError::CredentialAccessDenied)?;
        authority
            .authorize_load(capability)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        let authority = self
            .version_authority
            .as_ref()
            .ok_or(SecureStoreError::CredentialAccessDenied)?;
        authority
            .authorize_delete(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
}
