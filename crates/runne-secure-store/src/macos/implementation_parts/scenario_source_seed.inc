// Scenario-only generation-0 (legacy) source seeding for the isolated native
// migration qualification. Compiled only under the test-support feature: the
// encoder shapes are crate-private, so the disposable-host scenario cannot
// fabricate them externally, and production builds must never gain a
// legacy-item minting path. It grants no authority and widens no ACL: the
// item is created with the exact trusted-application set the authorized
// import path verifies, under the scenario's explicit disposable keychain.
#[cfg(feature = "test-support")]
use crate::ProviderCredentialSourceRevision;

#[cfg(feature = "test-support")]
impl MacOsProviderCredentialStore {
    /// Seeds one complete generation-0 source item: complete metadata without
    /// a source-slot version, with the record carrying the scenario's source
    /// revision exactly as the authorized import readback requires. Runs under
    /// the same non-interactive keychain acquisition as every store effect.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for an unsupported provider, an invalid
    /// exact access object, or any native creation, population or metadata
    /// commit failure. A failed population deletes the incomplete item.
    pub fn seed_generation_zero_source_scenario(
        &self,
        provider: ProviderCredentialId,
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        exact: &runne_macos_keychain_acl::ExactKeychainAccess,
        source_revision: ProviderCredentialSourceRevision,
    ) -> Result<(), SecureStoreError> {
        let scoped = self.scoped_provider_store(provider);
        scoped.validate_provider(provider)?;
        let metadata =
            ProviderCredentialMetadata::from_access_revision(access, exact.digest(), source_revision);
        let payload = StoredProviderCredential::encode_with_revision(
            material,
            access,
            exact.digest(),
            source_revision,
        )?;
        Self::with_noninteractive(|keychain| {
            let mut item = runne_macos_keychain_acl::create_empty_generic_password(
                keychain,
                &scoped.service,
                &scoped.account,
                &metadata.encode_incomplete(),
                exact,
            )
            .map_err(map_acl_error)?
            .finalize(exact)
            .map_err(map_acl_error)?;
            if item.set_password(&payload).is_err() {
                let _ = runne_macos_keychain_acl::delete_item(&item);
                return Err(SecureStoreError::ProviderCredentialOperationFailed);
            }
            runne_macos_keychain_acl::set_generic_password_metadata(&item, &metadata.encode())
                .map_err(map_acl_error)
        })
    }
}
