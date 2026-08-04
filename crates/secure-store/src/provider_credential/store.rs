/// Native provider credential lifecycle boundary.
pub trait ProviderCredentialStore: Send + Sync {
    /// # Errors
    ///
    /// Returns a typed secure-store failure when status cannot be determined.
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
