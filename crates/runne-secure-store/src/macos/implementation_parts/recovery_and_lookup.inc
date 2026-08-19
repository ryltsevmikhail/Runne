impl MacOsProviderCredentialStore {
    // Keep complete-copy selection and destructive steps visibly ordered.
    #[allow(clippy::too_many_lines)]
    fn reconcile_migration_backup(
        &self,
        keychain: &SecKeychain,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let Some((backup_metadata, backup_item)) =
            self.find_named_metadata(keychain, &self.migration_service())?
        else {
            return Ok(());
        };
        let current_access = ExactKeychainAccess::new(current.writer_path(), current.reader_path())
            .map_err(map_acl_error)?;
        let replacement_access =
            ExactKeychainAccess::new(replacement.writer_path(), replacement.reader_path())
                .map_err(map_acl_error)?;
        verify_migration_metadata(&backup_metadata, &backup_item, current, &current_access)?;

        let primary_metadata = self.find_named_metadata(keychain, &self.service)?;
        if !backup_metadata.is_complete() {
            let (primary_metadata, primary_item, source_service) = if let Some((metadata, item)) =
                primary_metadata
            {
                (metadata, item, self.service.clone())
            } else {
                let Some((metadata, item)) = self
                    .find_named_metadata(keychain, &self.source_alternate_service())?
                else {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                };
                (metadata, item, self.source_alternate_service())
            };
            if !primary_metadata.is_complete() {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            if primary_metadata.access_matches(current) {
                verify_migration_metadata(
                    &primary_metadata,
                    &primary_item,
                    current,
                    &current_access,
                )?;
            } else if primary_metadata.access_matches(replacement) {
                verify_migration_metadata(
                    &primary_metadata,
                    &primary_item,
                    replacement,
                    &replacement_access,
                )?;
            } else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Some((primary_encoded, _)) = self.find_named_item(keychain, &source_service)? else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            let primary = StoredProviderCredential::decode(&primary_encoded)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if !primary.metadata_matches(&primary_metadata) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            return runne_macos_keychain_acl::delete_item(&backup_item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete);
        }

        let Some((backup_encoded, _)) = self.find_migration_backup(keychain)? else {
            return Err(SecureStoreError::CredentialMigrationIncomplete);
        };
        let backup = StoredProviderCredential::decode(&backup_encoded)
            .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
        if !backup.metadata_matches(&backup_metadata) || !backup.access_matches(current) {
            return Err(SecureStoreError::CredentialMigrationIncomplete);
        }

        match primary_metadata {
            None => {
                runne_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                Err(SecureStoreError::CredentialMigrationIncomplete)
            }
            Some((primary_metadata, primary_item)) => {
                if !primary_metadata.is_complete() {
                    if primary_metadata.access_matches(current) {
                        verify_migration_metadata(
                            &primary_metadata,
                            &primary_item,
                            current,
                            &current_access,
                        )?;
                    } else if primary_metadata.access_matches(replacement) {
                        verify_migration_metadata(
                            &primary_metadata,
                            &primary_item,
                            replacement,
                            &replacement_access,
                        )?;
                    } else {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    runne_macos_keychain_acl::delete_item(&primary_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                    runne_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                }
                if primary_metadata.access_matches(current) {
                    verify_migration_metadata(
                        &primary_metadata,
                        &primary_item,
                        current,
                        &current_access,
                    )?;
                } else if primary_metadata.access_matches(replacement) {
                    verify_migration_metadata(
                        &primary_metadata,
                        &primary_item,
                        replacement,
                        &replacement_access,
                    )?;
                } else {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                }
                let Some((primary_encoded, _)) = self.find_primary_item(keychain)? else {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                };
                let primary = StoredProviderCredential::decode(&primary_encoded)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                if !primary.metadata_matches(&primary_metadata) {
                    return Err(SecureStoreError::CredentialMigrationIncomplete);
                }
                if primary.access_matches(current) {
                    if primary_encoded.as_slice() != backup_encoded.as_slice() {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    runne_macos_keychain_acl::delete_item(&backup_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
                } else if primary.access_matches(replacement) {
                    if primary.acl_set_digest() != replacement_access.digest() {
                        return Err(SecureStoreError::CredentialMigrationIncomplete);
                    }
                    runne_macos_keychain_acl::delete_item(&backup_item)
                        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
                } else {
                    Err(SecureStoreError::CredentialMigrationIncomplete)
                }
            }
        }
    }
    fn validate_provider(&self, provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        if provider.account() != self.account
            && self.account == ProviderCredentialId::OpenAi.account()
        {
            return Err(SecureStoreError::ProviderCredentialOperationFailed);
        }
        Ok(())
    }

    fn with_noninteractive<T>(
        operation: impl FnOnce(&SecKeychain) -> Result<T, SecureStoreError>,
    ) -> Result<T, SecureStoreError> {
        let _operation_lock = PROVIDER_CREDENTIAL_KEYCHAIN_LOCK
            .lock()
            .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
        let _process_lock = ProviderCredentialProcessLock::acquire().map_err(map_acl_error)?;
        let _interaction_lock =
            SecKeychain::disable_user_interaction().map_err(map_keychain_error)?;
        let keychain = SecKeychain::default().map_err(map_keychain_error)?;
        operation(&keychain)
    }

    fn find_metadata_pair(
        &self,
        keychain: &SecKeychain,
    ) -> Result<(CredentialMetadataItem, CredentialMetadataItem), SecureStoreError> {
        Ok((
            self.find_named_metadata(keychain, &self.service)?,
            self.find_named_metadata(keychain, &self.migration_service())?,
        ))
    }

    fn find_named_metadata(
        &self,
        keychain: &SecKeychain,
        service: &str,
    ) -> Result<CredentialMetadataItem, SecureStoreError> {
        runne_macos_keychain_acl::find_generic_password_metadata(keychain, service, &self.account)
            .map_err(map_acl_error)?
            .map(|metadata| {
                ProviderCredentialMetadata::decode(&metadata.bytes)
                    .map(|decoded| (decoded, metadata.item))
            })
            .transpose()
    }

    fn find_primary_item(
        &self,
        keychain: &SecKeychain,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        self.find_named_item(keychain, &self.service)
    }

    fn find_migration_backup(
        &self,
        keychain: &SecKeychain,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        self.find_named_item(keychain, &self.migration_service())
    }

    fn find_named_item(
        &self,
        keychain: &SecKeychain,
        service: &str,
    ) -> Result<CredentialKeychainItem, SecureStoreError> {
        #[cfg(test)]
        PROVIDER_CREDENTIAL_PASSWORD_READS.set(PROVIDER_CREDENTIAL_PASSWORD_READS.get() + 1);
        match keychain.find_generic_password(service, &self.account) {
            Ok((password, item)) => Ok(Some((Zeroizing::new(password.to_vec()), item))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(map_keychain_error(error)),
        }
    }

    fn migration_service(&self) -> String {
        format!("{}{PROVIDER_CREDENTIAL_MIGRATION_SUFFIX}", self.service)
    }
}

fn verify_item_acl(
    item: &SecKeychainItem,
    expected_digest: [u8; 32],
) -> Result<(), SecureStoreError> {
    runne_macos_keychain_acl::verify_item_access(item, expected_digest).map_err(map_acl_error)
}

fn verify_migration_metadata(
    metadata: &ProviderCredentialMetadata,
    item: &SecKeychainItem,
    access: &ProviderCredentialAccessPolicy,
    exact_access: &ExactKeychainAccess,
) -> Result<(), SecureStoreError> {
    if !metadata.access_matches(access) || metadata.acl_set_digest() != exact_access.digest() {
        return Err(SecureStoreError::CredentialMigrationIncomplete);
    }
    verify_item_acl(item, exact_access.digest())
        .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)
}
