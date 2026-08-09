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
        let source_revision = generate_provider_credential_source_revision()?;
        Self::with_noninteractive(|keychain| {
            let exact_access = ExactKeychainAccess::new(access.writer_path(), access.reader_path())
                .map_err(map_acl_error)?;
            access.remeasure().map_err(map_identity_access_error)?;
            let metadata = ProviderCredentialMetadata::from_access_revision(
                access,
                exact_access.digest(),
                source_revision,
            );
            let encoded = StoredProviderCredential::encode_with_revision(
                credential,
                access,
                exact_access.digest(),
                source_revision,
            )?;
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
                    gocode_macos_keychain_acl::set_generic_password_metadata(
                        &item,
                        &metadata.encode(),
                    )
                    .map_err(|_| SecureStoreError::CredentialEnrollmentIncomplete)?;
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
        self.load_provider_credential_record(provider, expected_access)
            .map(StoredProviderCredential::into_material)
    }

    fn load_provider_credential_source(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        self.load_provider_credential_record(provider, expected_access)?
            .into_source()
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
