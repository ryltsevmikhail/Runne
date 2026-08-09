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
            self.ensure_no_access_migration(keychain)?;
            recover_provider_credential_record(
                &mut self.source_slots(keychain, &exact_access),
                expected_access,
                exact_access.digest(),
            )
            .map_err(map_source_read_error)?
            .ok_or(SecureStoreError::ProviderCredentialNotFound)
        })
    }
}

fn map_source_read_error(error: SecureStoreError) -> SecureStoreError {
    if error == SecureStoreError::CredentialAclMigrationRequired {
        SecureStoreError::CredentialAccessDenied
    } else {
        error
    }
}
