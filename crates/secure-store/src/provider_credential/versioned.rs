use gocode_provider::CredentialVersionRef;

/// Opaque native operations for immutable provider credential versions.
///
/// References contain only non-secret provider/version identity. Credential
/// bytes are returned solely as zeroizing native-store material and never as
/// a serializable handle or reference payload.
pub trait NativeProviderCredentialVersionStore: Send + Sync {
    /// Idempotently creates immutable native material for a prepared version.
    ///
    /// # Errors
    ///
    /// Returns a closed validation, access, corruption, or backend failure.
    fn create_version(
        &self,
        reference: CredentialVersionRef,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;

    /// Loads native material for one exact active version reference.
    ///
    /// # Errors
    ///
    /// Returns a closed missing, access, corruption, or backend failure.
    fn load_version(
        &self,
        reference: CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;

    /// Idempotently deletes one exact native version.
    ///
    /// # Errors
    ///
    /// Returns a closed access, corruption, or backend failure.
    fn delete_version(&self, reference: CredentialVersionRef) -> Result<(), SecureStoreError>;
}
