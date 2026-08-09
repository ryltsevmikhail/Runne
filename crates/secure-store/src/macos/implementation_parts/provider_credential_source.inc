impl MacOsProviderCredentialStore {
    fn load_provider_credential_record(
        &self,
        provider: ProviderCredentialId,
        expected_access: &ProviderCredentialAccessPolicy,
    ) -> Result<StoredProviderCredential, SecureStoreError> {
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
            Ok(stored)
        })
    }
}
