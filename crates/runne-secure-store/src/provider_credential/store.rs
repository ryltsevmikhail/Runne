/// Native provider credential lifecycle boundary.
///
/// ```compile_fail
/// use runne_secure_store::{ProviderCredentialStore, ProviderCredentialAccessPolicy};
/// use runne_provider::AuthorizedCredentialLegacyRead;
/// fn bypass(store: &dyn ProviderCredentialStore, read: AuthorizedCredentialLegacyRead,
///     access: &ProviderCredentialAccessPolicy) {
///     let _ = store.load_authorized_legacy_source(read, access);
/// }
/// ```
pub trait ProviderCredentialStore: Send + Sync {
    /// # Errors
    ///
    /// Returns a typed runne-secure-store failure when status cannot be determined.
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError>;

    /// # Errors
    ///
    /// Returns a typed validation, identity, access or backend failure.
    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;

    /// # Errors
    ///
    /// Returns a typed missing, identity, access, corruption or backend failure.
    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;

    /// Atomically loads credential material and its stable source revision.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when source revision metadata is unavailable.
    fn load_provider_credential_source(
        &self,
        _provider: ProviderCredentialId,
        _expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)
    }

    /// # Errors
    ///
    /// Returns a typed identity, access, corruption or backend failure.
    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError>;

    /// # Errors
    ///
    /// Returns a typed identity, access, migration or backend failure.
    fn migrate_provider_credential_access(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
}

/// Crate-private native import entry: only the authenticated legacy port admits reads.
#[allow(clippy::redundant_pub_crate, reason = "native read authority must remain crate-private even if its parent is later exported")]
#[cfg(any(test, feature = "provider-credential-broker-writer"))]
pub(crate) trait AuthorizedLegacySourceStore: Send + Sync {
    fn delete_authorized_legacy_source(
        &self,
        _provider: ProviderCredentialId,
        _binding: &runne_provider::CredentialLegacyCleanupBinding,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    }
    fn load_authorized_legacy_source(
        &self,
        read: runne_provider::AuthorizedCredentialLegacyRead,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError>;
}

/// Linux native legacy-source admission: the authenticated in-process
/// legacy port admits reads/deletes through the same crate-private trait the
/// macOS implementation uses; the default methods carry the semantics.
#[cfg(all(target_os = "linux", feature = "provider-credential-broker-writer"))]
impl AuthorizedLegacySourceStore for crate::keyring::NativeKeyringStore {
    fn load_authorized_legacy_source(
        &self,
        read: runne_provider::AuthorizedCredentialLegacyRead,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        let provider = ProviderCredentialId::from_account(read.command().provider().as_str())
                .ok_or(SecureStoreError::ProviderCredentialOperationFailed)?;
            ProviderCredentialStore::load_provider_credential_source(self, provider, access)
    }
}
