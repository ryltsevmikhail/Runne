struct MacOsProviderCredentialSourceSlots<'a> {
    store: &'a MacOsProviderCredentialStore,
    keychain: &'a SecKeychain,
    exact_access: &'a ExactKeychainAccess,
}

impl MacOsProviderCredentialSourceSlots<'_> {
    fn service(&self, slot: ProviderCredentialSourceSlot) -> String {
        self.store.source_slot_service(slot)
    }

    fn find_metadata(
        &self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<runne_macos_keychain_acl::GenericPasswordMetadata>, SecureStoreError> {
        let metadata = runne_macos_keychain_acl::find_generic_password_metadata(
            self.keychain,
            &self.service(slot),
            &self.store.account,
        )
        .map_err(map_acl_error)?;
        if let Some(metadata) = &metadata {
            verify_item_acl(&metadata.item, self.exact_access.digest())?;
        }
        Ok(metadata)
    }

    // macOS 27 erases a saved item's partition ACL on the first
    // `SecKeychainItemModifyAttributesAndData`, so every slot mutation is a
    // verify-read, delete, and single atomic populated creation: the bytes and
    // final metadata travel in one `SecKeychainItemCreateFromContent` call and
    // `finalize` proves the saved item's ACL, deleting it on failure. A crash
    // between the delete and the recreation leaves the slot absent, which the
    // state machine already treats as a fresh create.
    fn recreate_slot(
        &self,
        slot: ProviderCredentialSourceSlot,
        old: &SecKeychainItem,
        metadata: &[u8],
        payload: &[u8],
    ) -> Result<(), SecureStoreError> {
        runne_macos_keychain_acl::delete_item(old).map_err(map_acl_error)?;
        runne_macos_keychain_acl::create_populated_generic_password(
            self.keychain,
            &self.service(slot),
            &self.store.account,
            metadata,
            payload,
            self.exact_access,
        )
        .and_then(|item| item.finalize(self.exact_access))
        .map(|_| ())
        .map_err(map_acl_error)
    }
}

impl ProviderCredentialSourceSlotBackend for MacOsProviderCredentialSourceSlots<'_> {
    fn load_metadata(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<Vec<u8>>, SecureStoreError> {
        self.find_metadata(slot)
            .map(|metadata| metadata.map(|metadata| metadata.bytes))
    }

    fn load_encrypted_payload(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
        #[cfg(test)]
        PROVIDER_CREDENTIAL_PASSWORD_READS.set(PROVIDER_CREDENTIAL_PASSWORD_READS.get() + 1);
        match self
            .keychain
            .find_generic_password(&self.service(slot), &self.store.account)
        {
            Ok((payload, _)) => Ok(Some(Zeroizing::new(payload.to_vec()))),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(map_keychain_error(error)),
        }
    }

    fn create_incomplete(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        metadata: &[u8],
    ) -> Result<(), SecureStoreError> {
        runne_macos_keychain_acl::create_empty_generic_password(
            self.keychain,
            &self.service(slot),
            &self.store.account,
            metadata,
            self.exact_access,
        )
        .and_then(|item| item.finalize(self.exact_access))
        .map(|_| ())
        .map_err(map_acl_error)
    }

    fn write_encrypted_payload(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        payload: &[u8],
    ) -> Result<(), SecureStoreError> {
        let old = self
            .find_metadata(slot)?
            .ok_or(SecureStoreError::CredentialEnrollmentIncomplete)?;
        self.recreate_slot(slot, &old.item, &old.bytes, payload)
    }

    fn atomic_write_metadata(
        &mut self,
        slot: ProviderCredentialSourceSlot,
        metadata: &[u8],
    ) -> Result<(), SecureStoreError> {
        let old = self
            .find_metadata(slot)?
            .ok_or(SecureStoreError::CredentialEnrollmentIncomplete)?;
        let (payload, _) = self
            .keychain
            .find_generic_password(&self.service(slot), &self.store.account)
            .map_err(map_keychain_error)?;
        self.recreate_slot(slot, &old.item, metadata, payload.as_ref())
    }

    fn delete_slot(
        &mut self,
        slot: ProviderCredentialSourceSlot,
    ) -> Result<(), SecureStoreError> {
        let Some(metadata) = self.find_metadata(slot)? else {
            return Ok(());
        };
        runne_macos_keychain_acl::delete_item(&metadata.item).map_err(map_acl_error)
    }
}

impl MacOsProviderCredentialStore {
    fn source_slot_service(&self, slot: ProviderCredentialSourceSlot) -> String {
        match slot {
            ProviderCredentialSourceSlot::Primary => self.service.clone(),
            ProviderCredentialSourceSlot::Alternate => self.source_alternate_service(),
        }
    }

    fn source_alternate_service(&self) -> String {
        format!("{}{PROVIDER_CREDENTIAL_SOURCE_ALTERNATE_SUFFIX}", self.service)
    }

    const fn source_slots<'a>(
        &'a self,
        keychain: &'a SecKeychain,
        exact_access: &'a ExactKeychainAccess,
    ) -> MacOsProviderCredentialSourceSlots<'a> {
        MacOsProviderCredentialSourceSlots {
            store: self,
            keychain,
            exact_access,
        }
    }

    fn ensure_no_access_migration(&self, keychain: &SecKeychain) -> Result<(), SecureStoreError> {
        if self
            .find_named_metadata(keychain, &self.migration_service())?
            .is_some()
        {
            Err(SecureStoreError::CredentialMigrationIncomplete)
        } else {
            Ok(())
        }
    }

    fn source_service_for_migration(
        &self,
        keychain: &SecKeychain,
    ) -> Result<String, SecureStoreError> {
        let mut selected: Option<(String, u64)> = None;
        let mut staged = false;
        for slot in [
            ProviderCredentialSourceSlot::Primary,
            ProviderCredentialSourceSlot::Alternate,
        ] {
            let service = self.source_slot_service(slot);
            let Some((metadata, _)) = self.find_named_metadata(keychain, &service)? else {
                continue;
            };
            staged = true;
            let generation = match metadata.source_slot() {
                None if slot == ProviderCredentialSourceSlot::Primary && metadata.is_complete() => {
                    0
                }
                Some(version)
                    if version.slot == slot
                        && version.state
                            == crate::provider_credential::source_update::ProviderCredentialSourceSlotState::Committed
                        && metadata.is_complete() =>
                {
                    version.generation
                }
                Some(version) if version.slot == slot => continue,
                None if slot == ProviderCredentialSourceSlot::Primary => continue,
                _ => return Err(SecureStoreError::CorruptProviderCredential),
            };
            match selected {
                Some((_, current)) if current == generation => {
                    return Err(SecureStoreError::CorruptProviderCredential);
                }
                Some((_, current)) if current > generation => {}
                _ => selected = Some((service, generation)),
            }
        }
        selected.map_or_else(
            || {
                Err(if staged {
                    SecureStoreError::CredentialMigrationIncomplete
                } else {
                    SecureStoreError::ProviderCredentialNotFound
                })
            },
            |(service, _)| Ok(service),
        )
    }
}
