impl MacOsProviderCredentialStore {
    // Keep crash boundaries in one linear sequence so mutation order remains auditable.
    #[allow(clippy::too_many_lines)]
    fn migrate_provider_credential_access_inner(
        &self,
        provider: ProviderCredentialId,
        current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
        failpoint: Option<CredentialMigrationFailpoint>,
    ) -> Result<(), SecureStoreError> {
        self.validate_provider(provider)?;
        current
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        if current.writer_identity() != replacement.writer_identity() {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        current.remeasure().map_err(map_identity_access_error)?;
        replacement.remeasure().map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            self.reconcile_migration_backup(keychain, current, replacement)?;
            let source_service = self.source_service_for_migration(keychain)?;
            let Some((metadata, metadata_item)) =
                self.find_named_metadata(keychain, &source_service)?
            else {
                return Err(SecureStoreError::ProviderCredentialNotFound);
            };
            let current_access =
                ExactKeychainAccess::new(current.writer_path(), current.reader_path())
                    .map_err(map_acl_error)?;
            let replacement_access =
                ExactKeychainAccess::new(replacement.writer_path(), replacement.reader_path())
                    .map_err(map_acl_error)?;
            replacement.remeasure().map_err(map_identity_access_error)?;
            let expected_digest = if metadata.access_matches(current) {
                current_access.digest()
            } else if metadata.access_matches(replacement) {
                replacement_access.digest()
            } else {
                return Err(SecureStoreError::CredentialAclMigrationRequired);
            };
            if metadata.acl_set_digest() != expected_digest {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&metadata_item, expected_digest)?;
            if !metadata.is_complete() {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Some((encoded, item)) = self.find_named_item(keychain, &source_service)? else {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            let stored = StoredProviderCredential::decode(&encoded)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if !stored.metadata_matches(&metadata) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            if !stored.access_matches(current) && !stored.access_matches(replacement) {
                return Err(SecureStoreError::CredentialAclMigrationRequired);
            }
            if stored.acl_set_digest() != expected_digest {
                return Err(SecureStoreError::CredentialAccessDenied);
            }
            verify_item_acl(&item, expected_digest)?;
            if stored.access_matches(replacement) {
                return verify_item_acl(&item, replacement_access.digest())
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete);
            }
            let source_revision = metadata.source_revision();
            let material = stored.into_material();
            for inactive_service in [self.service.clone(), self.source_alternate_service()] {
                if inactive_service == source_service {
                    continue;
                }
                let Some((inactive_metadata, inactive_item)) =
                    self.find_named_metadata(keychain, &inactive_service)?
                else {
                    continue;
                };
                inactive_metadata.validate_writer_current()?;
                verify_item_acl(&inactive_item, inactive_metadata.acl_set_digest())?;
                gocode_macos_keychain_acl::delete_item(&inactive_item)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            }
            let (current_metadata, replacement_metadata, replacement_encoded) =
                if let Some(revision) = source_revision {
                    (
                        ProviderCredentialMetadata::from_access_revision(
                            current,
                            current_access.digest(),
                            revision,
                        ),
                        ProviderCredentialMetadata::from_access_revision(
                            replacement,
                            replacement_access.digest(),
                            revision,
                        ),
                        StoredProviderCredential::encode_with_revision(
                            &material,
                            replacement,
                            replacement_access.digest(),
                            revision,
                        )?,
                    )
                } else {
                    (
                        ProviderCredentialMetadata::from_access(
                            current,
                            current_access.digest(),
                        ),
                        ProviderCredentialMetadata::from_access(
                            replacement,
                            replacement_access.digest(),
                        ),
                        StoredProviderCredential::encode(
                            &material,
                            replacement,
                            replacement_access.digest(),
                        )?,
                    )
                };
            let migration_service = self.migration_service();
            let backup_result = create_populated_provider_item(
                keychain,
                &migration_service,
                &self.account,
                &current_metadata,
                &current_access,
                &encoded,
                (failpoint == Some(CredentialMigrationFailpoint::BackupEmptyWritten))
                    .then_some(CredentialPopulationFailpoint::EmptyItemWritten),
            );
            if failpoint == Some(CredentialMigrationFailpoint::BackupEmptyWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let backup_item = backup_result?;
            verify_item_acl(&backup_item, current_access.digest())?;
            if failpoint == Some(CredentialMigrationFailpoint::BackupWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            gocode_macos_keychain_acl::delete_item(&item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            if failpoint == Some(CredentialMigrationFailpoint::PrimaryDeleted) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let replacement_result = create_populated_provider_item(
                keychain,
                &self.service,
                &self.account,
                &replacement_metadata,
                &replacement_access,
                &replacement_encoded,
                (failpoint == Some(CredentialMigrationFailpoint::ReplacementEmptyWritten))
                    .then_some(CredentialPopulationFailpoint::EmptyItemWritten),
            );
            if failpoint == Some(CredentialMigrationFailpoint::ReplacementEmptyWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            let Ok(replacement_item) = replacement_result else {
                gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service)
                    .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            };
            if verify_item_acl(&replacement_item, replacement_access.digest()).is_err() {
                if gocode_macos_keychain_acl::delete_item(&replacement_item).is_ok() {
                    let _ =
                        gocode_macos_keychain_acl::rename_item_service(&backup_item, &self.service);
                }
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            if failpoint == Some(CredentialMigrationFailpoint::ReplacementWritten) {
                return Err(SecureStoreError::CredentialMigrationIncomplete);
            }
            gocode_macos_keychain_acl::delete_item(&backup_item)
                .map_err(|_| SecureStoreError::CredentialMigrationIncomplete)?;
            Ok(())
        })
    }

}
