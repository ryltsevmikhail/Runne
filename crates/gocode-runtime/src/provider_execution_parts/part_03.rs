impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Creates, stores and activates one random 32-byte journal key.
    ///
    /// Secure storage happens before database activation, so an interrupted
    /// rotation can at worst leave unreferenced key material, never a durable
    /// ciphertext reference without its key.
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
            .activate_journal_key(binding)
            .map_err(map_execution_error)?;
        *self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)? = Some(binding);
        Ok(binding)
    }

}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Rebinds this process to an already active durable key after restart.
    pub fn use_existing_active_key(
        &self,
        binding: ProviderJournalKeyBinding,
    ) -> Result<(), RuntimeProviderExecutionError> {
        self.load_key(binding)?;
        *self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)? = Some(binding);
        Ok(())
    }

}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Validates and activates the durable key binding using metadata only.
    ///
    /// Key bytes remain unavailable until admitted journal I/O or recovery.
    pub fn preflight_existing_active_key(
        &self,
        runtime_authority_id: [u8; 16],
        database_generation: u64,
    ) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
        if !self.keyring.retains_multiple_provider_journal_keys() {
            return Err(RuntimeProviderExecutionError::KeyRetentionUnsupported);
        }
        let binding = self
            .store
            .active_journal_key_binding()
            .map_err(map_execution_error)?
            .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        if binding.runtime_authority_id() != runtime_authority_id
            || binding.database_generation() != database_generation
        {
            return Err(RuntimeProviderExecutionError::JournalKeyUnavailable);
        }
        let status = self
            .keyring
            .provider_journal_key_status(secure_ref_from_binding(binding)?)
            .map_err(map_secure_store_error)?;
        if status != ProviderJournalKeyStatus::Available {
            return Err(RuntimeProviderExecutionError::JournalKeyUnavailable);
        }
        *self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)? = Some(binding);
        Ok(binding)
    }

}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Encrypts and commits one normalized event.
    fn commit_polled_event(
        &self,
        context: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<ProviderJournalAppendOutcome, RuntimeProviderExecutionError> {
        if event.sequence() == u64::MAX {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let key = self.current_key()?;
        let material = self.load_key(key)?;
        let event_kind = event_kind_code(event.kind());
        let terminal = matches!(event.kind(), ProviderStreamEventKind::Finished { .. });
        let plaintext =
            serde_json::to_vec(event).map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
        let aad = event_aad(context, key, event.sequence(), event_kind, terminal);
        let encrypted = self.seal(&material, &aad, &plaintext)?;
        self.store
            .append_encrypted_event(&ProviderJournalAppendRequest {
                attempt_id: context.attempt_id,
                fencing_token: context.fencing_token,
                sequence: event.sequence(),
                event_kind,
                terminal,
                call_digest_version: context.call_digest_version,
                profile_digest: context.profile_digest,
                runtime_generation: context.runtime_generation,
                key,
                encrypted,
            })
            .map_err(map_execution_error)
    }

}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Polls exactly one adapter item and durably journals it before returning.
    ///
    /// If local commit cannot be proven after provider bytes arrive, the
    /// attempt is marked `Uncertain`; the caller receives no item to advance.
    pub async fn next_and_commit<A: ProviderPort + ?Sized>(
        &self,
        provider: &A,
        stream_id: &ProviderStreamId,
        cursor: StreamCursor,
        context: &ProviderEventJournalContext,
    ) -> Result<ProviderStreamItem, RuntimeProviderExecutionError> {
        self.store
            .begin_provider_poll(&ProviderPollRequest {
                attempt_id: context.attempt_id,
                fencing_token: context.fencing_token,
                cursor: cursor.sequence(),
                profile_digest: context.profile_digest,
                runtime_generation: context.runtime_generation,
            })
            .map_err(map_execution_error)?;
        let item = match provider.next(stream_id, cursor).await {
            Ok(item) => item,
            Err(_) => {
                self.store
                    .mark_execution_uncertain(context.attempt_id, context.fencing_token)
                    .map_err(|_| RuntimeProviderExecutionError::JournalCommitLost)?;
                return Err(RuntimeProviderExecutionError::AdapterStreamUnavailable);
            }
        };
        if self.commit_polled_event(context, item.event()).is_err() {
            self.store
                .mark_execution_uncertain(context.attempt_id, context.fencing_token)
                .map_err(|_| RuntimeProviderExecutionError::JournalCommitLost)?;
            return Err(RuntimeProviderExecutionError::JournalCommitLost);
        }
        Ok(item)
    }

}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Decrypts and validates every exact committed event for recovery.
    pub fn recover_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderStreamEvent>, RuntimeProviderExecutionError> {
        let encrypted = self
            .store
            .load_encrypted_events(attempt_id)
            .map_err(map_execution_error)?;
        encrypted
            .into_iter()
            .map(|record| {
                let material = self.load_key(record.key)?;
                let context = ProviderEventJournalContext {
                    attempt_id: record.attempt_id,
                    fencing_token: record.fencing_token,
                    call_digest_version: record.call_digest_version,
                    profile_digest: record.profile_digest,
                    runtime_generation: record.runtime_generation,
                };
                let aad = event_aad(
                    &context,
                    record.key,
                    record.sequence,
                    record.event_kind,
                    record.terminal,
                );
                let plaintext = Zeroizing::new(open_payload(&material, &aad, &record.encrypted)?);
                let event: ProviderStreamEvent = serde_json::from_slice(&plaintext)
                    .map_err(|_| RuntimeProviderExecutionError::JournalCorrupt)?;
                if event.sequence() != record.sequence
                    || event_kind_code(event.kind()) != record.event_kind
                    || matches!(event.kind(), ProviderStreamEventKind::Finished { .. })
                        != record.terminal
                {
                    return Err(RuntimeProviderExecutionError::JournalCorrupt);
                }
                Ok(event)
            })
            .collect()
    }

}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Loads and decrypts pending terminal outputs for idempotent application.
    pub fn recover_pending_terminal_outputs(
        &self,
    ) -> Result<Vec<RecoveredProviderTerminalOutput>, RuntimeProviderExecutionError> {
        self.store
            .pending_terminal_outbox()
            .map_err(map_execution_error)?
            .into_iter()
            .map(|record| {
                let material = self.load_key(record.key)?;
                let context = ProviderEventJournalContext {
                    attempt_id: record.attempt_id,
                    fencing_token: record.fencing_token,
                    call_digest_version: record.call_digest_version,
                    profile_digest: record.profile_digest,
                    runtime_generation: record.runtime_generation,
                };
                let aad = outbox_aad(
                    &context,
                    record.key,
                    record.terminal_sequence,
                    record.outbox_id,
                );
                let output =
                    Zeroizing::new(open_payload(&material, &aad, &record.encrypted_output)?);
                Ok(RecoveredProviderTerminalOutput { record, output })
            })
            .collect()
    }

}
