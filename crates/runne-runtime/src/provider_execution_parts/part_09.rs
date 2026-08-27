impl<'a, S, P> RuntimeProviderExecution<'a, dyn ProviderJournalKeyring, S, P>
where
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Creates, stores and activates one random 32-byte journal key.
    pub fn create_and_activate_key(
        &self,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
        key_version: u64,
    ) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
        if !self.keyring.retains_multiple_provider_journal_keys() {
            return Err(RuntimeProviderExecutionError::KeyRetentionUnsupported);
        }
        let key_id = self.random_nonzero::<16>()?;
        let key_bytes = self.random_nonzero::<32>()?;
        let key_ref = ProviderJournalKeyRef::new(
            key_id,
            key_version,
            runtime_authority_id,
            database_generation,
        )
        .map_err(map_secure_store_error)?;
        let material =
            ProviderJournalKeyMaterial::new(key_ref, key_bytes).map_err(map_secure_store_error)?;
        self.keyring
            .store_provider_journal_key(&material)
            .map_err(map_secure_store_error)?;
        let binding = binding_from_secure_ref(key_ref)?;
        self.store
            .activate_journal_key_with_keyring(self.keyring, binding)
            .map_err(map_execution_error)?;
        *self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)? = Some(binding);
        Ok(binding)
    }
}
