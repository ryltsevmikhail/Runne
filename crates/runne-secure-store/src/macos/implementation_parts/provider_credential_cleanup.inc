#[cfg(any(test, feature = "provider-credential-broker-writer"))]
impl MacOsProviderCredentialStore {
    fn delete_exact_legacy_source(
        &self,
        provider: ProviderCredentialId,
        binding: &runne_provider::CredentialLegacyCleanupBinding,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        if !matches!((provider, binding.destination().provider().as_str()),
            (ProviderCredentialId::OpenAi, "openai") | (ProviderCredentialId::DeepSeek, "deepseek")) {
            return Err(SecureStoreError::CredentialAccessDenied);
        }
        let store = self.scoped_provider_store(provider);
        store.validate_provider(provider)?;
        access.validate_writer_current().map_err(map_identity_access_error)?;
        access.remeasure().map_err(map_identity_access_error)?;
        let exact_access = ExactKeychainAccess::new(access.writer_path(), access.reader_path())
            .map_err(map_acl_error)?;
        Self::with_noninteractive(|keychain| {
            use crate::provider_credential::source_update::ProviderCredentialSourceSlot;
            store.ensure_no_access_migration(keychain)?;
            let mut candidates = Vec::new();
            for (slot, service) in [
                (ProviderCredentialSourceSlot::Alternate, store.source_alternate_service()),
                (ProviderCredentialSourceSlot::Primary, store.service.clone()),
            ] {
                let Some((metadata, item)) = store.find_named_metadata(keychain, &service)? else { continue; };
                crate::provider_credential::source_cleanup::validate_slot(slot, metadata.source_slot())?;
                if !metadata.is_complete() || !metadata.access_matches(access)
                    || metadata.acl_set_digest() != exact_access.digest() {
                    return Err(SecureStoreError::CorruptProviderCredential);
                }
                metadata.validate_writer_current()?;
                verify_item_acl(&item, exact_access.digest())?;
                let revision = metadata.source_revision()
                    .ok_or(SecureStoreError::ProviderCredentialSourceRevisionUnavailable)?;
                candidates.push((revision, item));
            }
            // No mutation occurs until every source slot has been checked under this lock.
            let item = crate::provider_credential::source_cleanup::select(binding, candidates)?;
            access.validate_writer_current().map_err(map_identity_access_error)?;
            access.remeasure().map_err(map_identity_access_error)?;
            if let Some(item) = item {
                runne_macos_keychain_acl::delete_item(&item).map_err(map_acl_error)?;
            }
            Ok(())
        })
    }
}
