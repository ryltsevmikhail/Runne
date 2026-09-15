impl ProviderCredentialStore for MacOsProviderCredentialStore {
    fn delete_provider_credential(&self, provider: ProviderCredentialId) -> Result<(), SecureStoreError> {
        self.delete_provider_credential_inner(provider)
    }

    fn migrate_provider_credential_access(
        &self, provider: ProviderCredentialId, current: &ProviderCredentialAccessPolicy,
        replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.migrate_provider_credential_access_inner(provider, current, replacement, None)
    }
    fn provider_credential_status(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
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
        Self::with_noninteractive(|keychain| {
            store.ensure_no_access_migration(keychain)?;
            let mut slots = store.source_slots(keychain, &exact_access);
            committed_provider_credential_source_slot(
                &mut slots,
                expected_access,
                exact_access.digest(),
            )
            .map(|slot| {
                slot.map_or(
                    ProviderCredentialStatus::Missing,
                    |_| ProviderCredentialStatus::Configured,
                )
            })
            .map_err(map_source_read_error)
        })
    }

    fn store_provider_credential(
        &self,
        provider: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        access
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            let exact_access = ExactKeychainAccess::new(access.writer_path(), access.reader_path())
                .map_err(map_acl_error)?;
            access.remeasure().map_err(map_identity_access_error)?;
            store.ensure_no_access_migration(keychain)?;
            let source_revision = generate_provider_credential_source_revision()?;
            commit_provider_credential_source_update(
                &mut store.source_slots(keychain, &exact_access),
                credential,
                access,
                exact_access.digest(),
                source_revision,
            )
            .map(|_| ())
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

}

#[cfg(any(test, feature = "provider-credential-broker-writer"))]
impl crate::provider_credential::AuthorizedLegacySourceStore for MacOsProviderCredentialStore {
    fn delete_authorized_legacy_source(
        &self, provider: ProviderCredentialId,
        binding: &runne_provider::CredentialLegacyCleanupBinding,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.delete_exact_legacy_source(provider, binding, access)
    }
    fn load_authorized_legacy_source(
        &self,
        read: runne_provider::AuthorizedCredentialLegacyRead,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        access.validate_writer_current().map_err(map_identity_access_error)?;
        let command = read.command();
        if command.action() != runne_provider::CredentialOperationAction::MigrateLegacy {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let runne_provider::CredentialBrokerTarget::LegacyImport(version) = command.target() else {
            return Err(SecureStoreError::CredentialAccessDenied);
        };
        if version.provider() != command.provider() {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let provider = ProviderCredentialId::from_account(command.provider().as_str())
            .ok_or(SecureStoreError::UnsupportedSecureStoreBackend)?;
        self.load_admitted_provider_credential_record(provider, access)?.into_source()
    }
}

impl MacOsProviderCredentialStore {
    fn delete_provider_credential_inner(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        Self::with_noninteractive(|keychain| {
            for service in [
                store.source_alternate_service(),
                store.migration_service(),
                store.service.clone(),
            ] {
                let Some((metadata, item)) = store.find_named_metadata(keychain, &service)? else {
                    continue;
                };
                metadata.validate_writer_current()?;
                verify_item_acl(&item, metadata.acl_set_digest())?;
                runne_macos_keychain_acl::delete_item(&item).map_err(map_acl_error)?;
            }
            Ok(())
        })
    }

}
