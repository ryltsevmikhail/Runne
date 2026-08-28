use super::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialNativeCreateClaim,
    CredentialVersionRef, NativeCredentialDeletionProof, NativeKeyringStore,
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialMaterial,
    ProviderCredentialStatus, SecureStoreError, StoredProviderCredential, access_digest,
    provider_id, validate_reader_or_writer, validate_stored,
};

impl NativeProviderCredentialVersionStore for NativeKeyringStore {
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        provider_id(reference)?;
        validate_reader_or_writer(access)?;
        let Some(encoded) = Self::read_version(reference)?.filter(|bytes| !bytes.is_empty()) else {
            return Ok(ProviderCredentialStatus::Missing);
        };
        validate_stored(&StoredProviderCredential::decode(&encoded)?, access)?;
        Ok(ProviderCredentialStatus::Configured)
    }

    #[cfg(not(target_os = "macos"))]
    fn version_source_revision(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<crate::ProviderCredentialSourceRevision, SecureStoreError> {
        provider_id(reference)?;
        validate_reader_or_writer(access)?;
        let encoded =
            Self::read_version(reference)?.ok_or(SecureStoreError::ProviderCredentialNotFound)?;
        let stored = StoredProviderCredential::decode(&encoded)?;
        validate_stored(&stored, access)?;
        stored
            .source_revision()
            .ok_or(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)
    }

    #[cfg(target_os = "macos")]
    fn version_source_revision(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<crate::ProviderCredentialSourceRevision, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let authority = self.version_authority()?;
        let reference = claim.version_ref().clone();
        provider_id(&reference)?;
        access.validate_writer_current()?;
        access.remeasure()?;
        if let Some(existing) = Self::read_version(&reference)? {
            let stored = StoredProviderCredential::decode(&existing)?;
            validate_stored(&stored, access)?;
            if stored.material_matches(credential) {
                return Ok(());
            }
            return Err(SecureStoreError::ProviderCredentialOperationFailed);
        }
        let authorization = authority
            .authorize_create(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        if authorization.version_ref() != &reference {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let source_revision = *claim.source_revision_id();
        drop(authorization);
        let encoded = StoredProviderCredential::encode_with_revision(
            credential,
            access,
            access_digest(access),
            crate::ProviderCredentialSourceRevision::new(source_revision)?,
        )?;
        Self::write_version(&reference, &encoded)
    }

    fn load_version(
        &self,
        capability: &CredentialDispatchCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        let reference = self
            .version_authority()?
            .authorize_load(capability)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Self::load_provider_version(reference, access)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        let authority = self.version_authority()?;
        let reference = authority
            .authorize_delete(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        Self::delete_version_ref(reference)?;
        authority
            .prove_deletion(claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }
}
