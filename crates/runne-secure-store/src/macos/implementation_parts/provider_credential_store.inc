impl ProviderCredentialStore for MacOsProviderCredentialStore {
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

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        access
            .validate_writer_current()
            .map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        let exact_access = ExactKeychainAccess::new(access.writer_path(), access.reader_path())
            .map_err(map_acl_error)?;
        Self::with_noninteractive(|keychain| {
            for service in [
                store.source_alternate_service(),
                store.migration_service(),
                store.service.clone(),
            ] {
                let Some((metadata, item)) = store.find_named_metadata(keychain, &service)? else {
                    continue;
                };
                metadata.validate_delete_access(access, exact_access.digest())?;
                verify_item_acl(&item, metadata.acl_set_digest())?;
                access.remeasure().map_err(map_identity_access_error)?;
                runne_macos_keychain_acl::delete_item(&item).map_err(map_acl_error)?;
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
