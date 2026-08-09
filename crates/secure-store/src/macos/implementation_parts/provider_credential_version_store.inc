impl NativeProviderCredentialVersionStore for MacOsProviderCredentialStore {
    fn version_status(
        &self,
        reference: &CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.version_store(reference)?
            .provider_credential_status(ProviderCredentialId::OpenAi, access)
    }

    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let authority = self.version_authority()?;
        let reference = claim.version_ref().clone();
        self.version_store(&reference)?.create_immutable_version(
            credential,
            access,
            || {
                let authorization = authority
                    .authorize_create(&claim)
                    .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
                if authorization.version_ref() != &reference {
                    return Err(SecureStoreError::CredentialAccessDenied);
                }
                Ok(authorization)
            },
        )
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
        self.version_store(reference)?
            .load_provider_credential(ProviderCredentialId::OpenAi, access)
    }

    fn delete_version(
        &self,
        claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        let authority = self.version_authority()?;
        let reference = authority
            .authorize_delete(&claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)?;
        self.version_store(reference)?
            .delete_provider_credential(ProviderCredentialId::OpenAi)?;
        authority
            .prove_deletion(claim)
            .map_err(|_| SecureStoreError::CredentialAccessDenied)
    }
}

impl MacOsProviderCredentialStore {
    fn create_immutable_version<Authorization>(
        &self,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        validate_authority: impl FnOnce() -> Result<Authorization, SecureStoreError>,
    ) -> Result<(), SecureStoreError> {
        access
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        let exact_access =
            ExactKeychainAccess::new(access.writer_path(), access.reader_path())
                .map_err(map_acl_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        let metadata = ProviderCredentialMetadata::from_access(access, exact_access.digest());
        let encoded = StoredProviderCredential::encode(credential, access, exact_access.digest())?;
        Self::with_noninteractive(|keychain| {
            let authorization = validate_authority()?;
            let result = match self.find_metadata_pair(keychain)? {
                (None, None) => create_populated_provider_item(
                    keychain,
                    &self.service,
                    &self.account,
                    &metadata,
                    &exact_access,
                    &encoded,
                    None,
                )
                .map(|_| ()),
                (Some((existing_metadata, metadata_item)), None) => {
                    existing_metadata.validate_writer_current()?;
                    if !existing_metadata.access_matches(access)
                        || existing_metadata.acl_set_digest() != exact_access.digest()
                    {
                        return Err(SecureStoreError::CredentialAccessDenied);
                    }
                    verify_item_acl(&metadata_item, exact_access.digest())?;
                    if !existing_metadata.is_complete() {
                        gocode_macos_keychain_acl::delete_item(&metadata_item)
                            .map_err(map_acl_error)?;
                        return create_populated_provider_item(
                            keychain,
                            &self.service,
                            &self.account,
                            &metadata,
                            &exact_access,
                            &encoded,
                            None,
                        )
                        .map(|_| ());
                    }
                    let Some((existing, item)) = self.find_primary_item(keychain)? else {
                        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
                    };
                    let stored = StoredProviderCredential::decode(&existing)?;
                    if !stored.metadata_matches(&existing_metadata)
                        || !stored.access_matches(access)
                        || stored.acl_set_digest() != exact_access.digest()
                    {
                        return Err(SecureStoreError::CorruptProviderCredential);
                    }
                    verify_item_acl(&item, exact_access.digest())?;
                    stored.into_material().with_bytes(|existing| {
                        credential.with_bytes(|incoming| {
                            if existing == incoming {
                                Ok(())
                            } else {
                                Err(SecureStoreError::ProviderCredentialOperationFailed)
                            }
                        })
                    })
                }
                _ => Err(SecureStoreError::CredentialMigrationIncomplete),
            };
            drop(authorization);
            result
        })
    }

    fn version_store(
        &self,
        reference: &CredentialVersionRef,
    ) -> Result<Self, SecureStoreError> {
        if reference.provider().as_str() != ProviderCredentialId::OpenAi.account() {
            return Err(SecureStoreError::ProviderCredentialOperationFailed);
        }
        Ok(Self {
            service: format!(
                "{}.version.{}.{}",
                self.service,
                reference.version(),
                encode_hex(reference.ref_digest())
            ),
            account: self.account.clone(),
            version_authority: self.version_authority.clone(),
        })
    }

    fn version_authority(&self) -> Result<&NativeCredentialAuthority, SecureStoreError> {
        self.version_authority
            .as_ref()
            .ok_or(SecureStoreError::CredentialAccessDenied)
    }
}
