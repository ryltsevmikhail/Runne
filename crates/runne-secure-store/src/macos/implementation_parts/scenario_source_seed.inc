// Scenario-only generation-0 (legacy) source seeding for the isolated native
// migration qualification. Compiled only under the test-support feature: the
// encoder shapes are crate-private, so the disposable-host scenario cannot
// fabricate them externally, and production builds must never gain a
// legacy-item minting path. It grants no authority and widens no ACL: the
// item is created with the exact trusted-application set the authorized
// import path verifies, under the scenario's explicit disposable keychain.
#[cfg(feature = "test-support")]
use crate::ProviderCredentialSourceRevision;

/// Scenario-facing placement of one committed fixture slot: the physical
/// slot (primary or alternate) and its committed generation.
#[cfg(feature = "test-support")]
pub struct ScenarioSourceSlotSeed {
    pub alternate: bool,
    pub generation: u64,
}

#[cfg(feature = "test-support")]
impl MacOsProviderCredentialStore {
    /// Seeds one complete generation-0 source item: complete metadata without
    /// a source-slot version, with the record carrying the scenario's source
    /// revision exactly as the authorized import readback requires. Runs under
    /// the same non-interactive keychain acquisition as every store effect.
    /// The payload and complete metadata are written in the single atomic
    /// creation step (macOS 27 erases the partition ACL on any later
    /// modification) and `finalize` deletes the item if the saved ACL readback
    /// fails.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for an unsupported provider, an invalid
    /// exact access object, or any native creation failure. A failed saved-item
    /// ACL verification deletes the item.
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
            runne_macos_keychain_acl::create_populated_generic_password(
                keychain,
                &scoped.service,
                &scoped.account,
                &metadata.encode(),
                &payload,
                exact,
            )
            .and_then(|item| item.finalize(exact))
            .map(|_| ())
            .map_err(map_acl_error)
        })
    }

/// Seeds one complete committed source-slot item (denial fixtures only):
/// Primary keeps the generation-zero shape; the alternate item carries a
/// real slot/generation/committed version exactly as a rotation would
/// write. Same exact-ACL atomic populated creation and fail-closed
/// saved-item verification as the generation-zero seeding above.
///
/// # Errors
///
/// Returns a closed failure for an unsupported provider, an invalid exact
/// access object, or any native creation failure. A failed saved-item ACL
/// verification deletes the item.
pub fn seed_committed_source_slot_scenario(
    &self,
    provider: ProviderCredentialId,
    seed: &ScenarioSourceSlotSeed,
        material: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
        exact: &runne_macos_keychain_acl::ExactKeychainAccess,
        source_revision: ProviderCredentialSourceRevision,
    ) -> Result<(), SecureStoreError> {
        use crate::provider_credential::source_update::{
            ProviderCredentialSourceSlot, ProviderCredentialSourceSlotState,
            ProviderCredentialSourceSlotVersion,
        };
        let scoped = self.scoped_provider_store(provider);
        scoped.validate_provider(provider)?;
        let slot = if seed.alternate {
            ProviderCredentialSourceSlot::Alternate
        } else {
            ProviderCredentialSourceSlot::Primary
        };
        let service = if seed.alternate {
            scoped.source_alternate_service()
        } else {
            scoped.service.clone()
        };
        let version = ProviderCredentialSourceSlotVersion::new(
            slot,
            seed.generation,
            ProviderCredentialSourceSlotState::Committed,
        )?;
        let metadata =
            ProviderCredentialMetadata::from_source_slot(access, exact.digest(), source_revision, version);
        let payload = StoredProviderCredential::encode_with_revision(
            material,
            access,
            exact.digest(),
            source_revision,
        )?;
        Self::with_noninteractive(|keychain| {
            runne_macos_keychain_acl::create_populated_generic_password(
                keychain,
                &service,
                &scoped.account,
                &metadata.encode(),
                &payload,
                exact,
            )
            .and_then(|item| item.finalize(exact))
            .map(|_| ())
            .map_err(map_acl_error)
        })
    }

    /// Removes one source-slot item under the same non-interactive keychain
    /// acquisition. Denial fixtures only: models the old-slot deletion side of
    /// a native rotation without touching durable state.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for an unsupported provider or a native
    /// lookup/deletion failure; a missing slot is not an error.
    pub fn remove_source_slot_scenario(
        &self,
        provider: ProviderCredentialId,
        alternate: bool,
    ) -> Result<(), SecureStoreError> {
        let scoped = self.scoped_provider_store(provider);
        scoped.validate_provider(provider)?;
        let service = if alternate {
            scoped.source_alternate_service()
        } else {
            scoped.service.clone()
        };
        Self::with_noninteractive(|keychain| match scoped.find_named_metadata(keychain, &service)? {
            Some((_, item)) => runne_macos_keychain_acl::delete_item(&item).map_err(map_acl_error),
            None => Ok(()),
        })
    }
}
