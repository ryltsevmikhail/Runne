// Versioned adapter over the single bound login-Keychain item.
//
// The item holds exactly one material per provider. Version references still
// validate the provider scope, but resolve to that one item: the CLI writes the
// active credential directly, without a second lifecycle silo.

fn provider_from_version_ref(
    reference: &CredentialVersionRef,
) -> Result<ProviderCredentialId, SecureStoreError> {
    ProviderCredentialId::from_account(reference.provider().as_str())
        .ok_or(SecureStoreError::UnsupportedSecureStoreBackend)
}

impl MacOsPlainProviderCredentialStore {
    pub(crate) fn load_provider_version_for_verification(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.load_provider_credential(provider_from_version_ref(reference)?, access)
    }
}

impl NativeProviderCredentialVersionStore for MacOsPlainProviderCredentialStore {
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.status_for(provider_from_version_ref(reference)?, access)
    }

    fn version_source_revision(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSourceRevision, SecureStoreError> {
        let source = self.load_provider_credential_source(provider_from_version_ref(reference)?, access)?;
        Ok(source.revision())
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.store_provider_credential(provider_from_version_ref(claim.version_ref())?, credential, access)
    }

    fn load_version(
        &self,
        capability: &CredentialDispatchCapability,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.load_provider_credential(provider_from_version_ref(capability.version_ref())?, access)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        let provider = provider_from_version_ref(claim.version_ref())?;
        self.delete_provider_credential(provider)?;
        self.authority
            .as_ref()
            .ok_or(SecureStoreError::UnsupportedSecureStoreBackend)?
            .prove_deletion(claim)
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
    }
}
