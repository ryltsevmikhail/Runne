impl ProviderCredentialStore for MacOsProviderCredentialStore {
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        self.validate_provider(provider)?;
        expected_access
            .validate_writer_or_reader_current()
            .map_err(map_identity_access_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        let exact_access =
            ExactKeychainAccess::new(expected_access.writer_path(), expected_access.reader_path())
                .map_err(map_acl_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| match self.find_metadata_pair(keychain)? {
            (None, None) => Ok(ProviderCredentialStatus::Missing),
            (Some((metadata, item)), None) => {
                if !metadata.access_matches(expected_access)
                    || metadata.acl_set_digest() != exact_access.digest()
                {
                    return Err(SecureStoreError::CredentialAccessDenied);
                }
                verify_item_acl(&item, exact_access.digest())?;
                if !metadata.is_complete() {
                    return Err(SecureStoreError::CredentialEnrollmentIncomplete);
                }
                Ok(ProviderCredentialStatus::Configured)
            }
            _ => Err(SecureStoreError::CredentialMigrationIncomplete),
        })
    }

    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        access
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            let exact_access = ExactKeychainAccess::new(access.writer_path(), access.reader_path())
                .map_err(map_acl_error)?;
            access.remeasure().map_err(map_identity_access_error)?;
            let metadata = ProviderCredentialMetadata::from_access(access, exact_access.digest());
            let encoded =
                StoredProviderCredential::encode(credential, access, exact_access.digest())?;
            match self.find_metadata_pair(keychain)? {
                (Some((existing_metadata, metadata_item)), None) => {
                    existing_metadata.validate_writer_current()?;
                    if !existing_metadata.access_matches(access) {
                        return Err(SecureStoreError::CredentialAclMigrationRequired);
                    }
                    if existing_metadata.acl_set_digest() != exact_access.digest() {
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
                    let Some((existing, mut item)) = self.find_primary_item(keychain)? else {
                        return Err(SecureStoreError::CredentialEnrollmentIncomplete);
                    };
                    let stored = StoredProviderCredential::decode(&existing)?;
                    if !stored.metadata_matches(&existing_metadata) {
                        return Err(SecureStoreError::CorruptProviderCredential);
                    }
                    if !stored.access_matches(access) {
                        return Err(SecureStoreError::CredentialAclMigrationRequired);
                    }
                    verify_item_acl(&item, exact_access.digest())?;
                    item.set_password(&encoded).map_err(map_keychain_error)?;
                    verify_item_acl(&item, exact_access.digest())
                }
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
                _ => Err(SecureStoreError::CredentialMigrationIncomplete),
            }
        })
    }

    fn load_provider_credential(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.validate_provider(provider)?;
        expected_access
            .validate_reader_current()
            .map_err(map_identity_access_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        let exact_access =
            ExactKeychainAccess::new(expected_access.writer_path(), expected_access.reader_path())
                .map_err(map_acl_error)?;
        expected_access
            .remeasure()
            .map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            let (metadata, metadata_item) = match self.find_metadata_pair(keychain)? {
                (Some(primary), None) => primary,
                (None, None) => return Err(SecureStoreError::ProviderCredentialNotFound),
                _ => return Err(SecureStoreError::CredentialMigrationIncomplete),
            };
            if !metadata.access_matches(expected_access)
                || metadata.acl_set_digest() != exact_access.digest()
            {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&metadata_item, exact_access.digest())?;
            if !metadata.is_complete() {
                return Err(SecureStoreError::CredentialEnrollmentIncomplete);
            }
            let Some((encoded, item)) = self.find_primary_item(keychain)? else {
                return Err(SecureStoreError::CredentialEnrollmentIncomplete);
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            if !stored.metadata_matches(&metadata) {
                return Err(SecureStoreError::CorruptProviderCredential);
            }
            if !stored.access_matches(expected_access)
                || stored.acl_set_digest() != exact_access.digest()
            {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&item, exact_access.digest())?;
            Ok(stored.into_material())
        })
    }

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        Self::with_noninteractive(|keychain| {
            let (primary, backup) = self.find_metadata_pair(keychain)?;
            for (metadata, item) in [backup, primary].into_iter().flatten() {
                metadata.validate_writer_current()?;
                verify_item_acl(&item, metadata.acl_set_digest())?;
                gocode_macos_keychain_acl::delete_item(&item).map_err(map_acl_error)?;
            }
            Ok(())
        })
    }

    fn migrate_provider_credential_access(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.migrate_provider_credential_access_inner(provider, current, replacement, None)
    }
}

impl NativeProviderCredentialVersionStore for MacOsProviderCredentialStore {
    fn create_version(
        &self,
        reference: CredentialVersionRef,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let version_store = self.version_store(&reference)?;
        match version_store.provider_credential_status(ProviderCredentialId::OpenAi, access)? {
            ProviderCredentialStatus::Configured => {
                if version_store.version_material_matches(credential, access)? {
                    Ok(())
                } else {
                    Err(SecureStoreError::ProviderCredentialOperationFailed)
                }
            }
            ProviderCredentialStatus::Missing => version_store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                credential,
                access,
            ),
            ProviderCredentialStatus::Unsupported => {
                Err(SecureStoreError::UnsupportedSecureStoreBackend)
            }
        }
    }

    fn load_version(
        &self,
        reference: CredentialVersionRef,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        self.version_store(&reference)?
            .load_provider_credential(ProviderCredentialId::OpenAi, access)
    }

    fn delete_version(&self, reference: CredentialVersionRef) -> Result<(), SecureStoreError> {
        self.version_store(&reference)?
            .delete_provider_credential(ProviderCredentialId::OpenAi)
    }
}

impl MacOsProviderCredentialStore {
    fn version_material_matches(
        &self,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<bool, SecureStoreError> {
        access
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        let exact_access =
            ExactKeychainAccess::new(access.writer_path(), access.reader_path())
                .map_err(map_acl_error)?;
        Self::with_noninteractive(|keychain| {
            let (metadata, metadata_item) = match self.find_metadata_pair(keychain)? {
                (Some(primary), None) => primary,
                _ => return Err(SecureStoreError::CredentialMigrationIncomplete),
            };
            if !metadata.is_complete()
                || !metadata.access_matches(access)
                || metadata.acl_set_digest() != exact_access.digest()
            {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&metadata_item, exact_access.digest())?;
            let Some((encoded, item)) = self.find_primary_item(keychain)? else {
                return Err(SecureStoreError::CredentialEnrollmentIncomplete);
            };
            let stored = StoredProviderCredential::decode(&encoded)?;
            if !stored.metadata_matches(&metadata)
                || !stored.access_matches(access)
                || stored.acl_set_digest() != exact_access.digest()
            {
                return Err(SecureStoreError::CorruptProviderCredential);
            }
            verify_item_acl(&item, exact_access.digest())?;
            let matches = stored.into_material().with_bytes(|existing| {
                credential.with_bytes(|incoming| existing == incoming)
            });
            Ok(matches)
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
        })
    }
}
