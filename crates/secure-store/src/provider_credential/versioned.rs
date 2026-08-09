use gocode_provider::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialVersionRef,
    NativeCredentialDeletionProof,
};

/// Opaque native operations for immutable provider credential versions.
///
/// References contain only non-secret provider/version identity. Credential
/// bytes are returned solely as zeroizing native-store material and never as
/// a serializable handle or reference payload.
pub trait NativeProviderCredentialVersionStore: Send + Sync {
    /// Validates non-secret native presence, metadata and canonical ref scope.
    ///
    /// # Errors
    ///
    /// Returns a closed access, corruption, missing-metadata, or backend failure.
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError>;

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

    /// Loads native material for one exact active dispatch capability.
    ///
    /// ```compile_fail
    /// use gocode_provider::{CredentialVersionRef, ProviderId};
    /// use gocode_secure_store::{NativeProviderCredentialStore,
    ///     NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy};
    /// let store = NativeProviderCredentialStore::new();
    /// let reference = CredentialVersionRef::new(ProviderId::new("openai")?, 1)?;
    /// let access: ProviderCredentialAccessPolicy = todo!();
    /// let _ = store.load_version(reference, &access);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a closed missing, access, corruption, or backend failure.
    fn load_version(
        &self,
        capability: &CredentialDispatchCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError>;

    /// Idempotently deletes the exact version owned by an exclusive GC claim.
    ///
    /// # Errors
    ///
    /// Returns a closed access, corruption, or backend failure.
    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError>;
}
