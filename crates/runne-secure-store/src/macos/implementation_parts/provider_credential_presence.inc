impl MacOsProviderCredentialStore {
    pub(crate) fn legacy_source_metadata_presence(
        &self,
        provider: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<bool, SecureStoreError> {
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        access.validate_reader_current().map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        Self::with_noninteractive(|keychain| {
            let services = [store.service.clone(), store.source_alternate_service(), store.migration_service()];
            let present = crate::provider_credential::legacy_presence::inspect(|slot| {
                // Decode metadata only: no secret load, recovery, ACL update or deletion.
                store.find_named_metadata(keychain, &services[slot]).map(|item| item.is_some())
            })?;
            access.validate_reader_current().map_err(map_identity_access_error)?;
            access.remeasure().map_err(map_identity_access_error)?;
            Ok(present)
        })
    }
}
