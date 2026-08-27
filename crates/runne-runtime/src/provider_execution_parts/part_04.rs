impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Marks exact authoritative Conversation receipt and settles the attempt.
    pub fn acknowledge_terminal_output(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), RuntimeProviderExecutionError> {
        self.store
            .acknowledge_terminal_outbox(outbox_id, receipt_digest)
            .map_err(map_execution_error)
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    fn rebind_forward_active_key(
        &self,
        previous: ProviderJournalKeyBinding,
    ) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
        let next = self
            .store
            .active_journal_key_binding()
            .map_err(map_execution_error)?
            .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        if next.runtime_authority_id() != previous.runtime_authority_id()
            || next.database_generation() != previous.database_generation()
            || next.key_version() <= previous.key_version()
        {
            return Err(RuntimeProviderExecutionError::JournalKeyUnavailable);
        }
        self.load_key(next)?;
        let mut active_key = self
            .active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)?;
        if active_key.is_some_and(|active| active.key_version() > next.key_version()) {
            return Err(RuntimeProviderExecutionError::JournalKeyUnavailable);
        }
        *active_key = Some(next);
        Ok(next)
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Applies every pending terminal output through an idempotent
    /// authoritative application boundary, then durably acknowledges its
    /// exact receipt.
    pub fn apply_pending_terminal_outputs<
        A: ProviderTerminalOutboxApplication,
        O: ProviderRecoveryObserver,
    >(
        &self,
        application: &A,
        observer: &O,
    ) -> Result<usize, RuntimeProviderExecutionError> {
        let pending = self.recover_pending_terminal_outputs()?;
        let mut applied = 0_usize;
        for recovered in pending {
            let receipt_digest = application
                .complete_provider_terminal(recovered.record(), recovered.output())
                .map_err(|error| match error {
                    ProviderTerminalApplicationError::Unavailable => {
                        RuntimeProviderExecutionError::ApplicationUnavailable
                    }
                    ProviderTerminalApplicationError::Conflict => {
                        RuntimeProviderExecutionError::ApplicationConflict
                    }
                })?;
            if receipt_digest == [0; 32] {
                return Err(RuntimeProviderExecutionError::ApplicationConflict);
            }
            self.acknowledge_terminal_output(recovered.record().outbox_id, receipt_digest)?;
            let _ = observer.observe_recovered_terminal_output();
            applied = applied
                .checked_add(1)
                .ok_or(RuntimeProviderExecutionError::ApplicationConflict)?;
        }
        Ok(applied)
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Applies only the exact foreground attempt outbox and acknowledges it.
    pub fn apply_terminal_output_for_attempt<A: ProviderTerminalOutboxApplication>(
        &self,
        attempt_id: DispatchAttemptId,
        application: &A,
    ) -> Result<bool, RuntimeProviderExecutionError> {
        let mut matching = self
            .recover_pending_terminal_outputs()?
            .into_iter()
            .filter(|recovered| recovered.record().attempt_id == attempt_id);
        let Some(recovered) = matching.next() else {
            return Ok(false);
        };
        if matching.next().is_some() {
            return Err(RuntimeProviderExecutionError::ApplicationConflict);
        }
        let receipt_digest = application
            .complete_provider_terminal(recovered.record(), recovered.output())
            .map_err(|error| match error {
                ProviderTerminalApplicationError::Unavailable => {
                    RuntimeProviderExecutionError::ApplicationUnavailable
                }
                ProviderTerminalApplicationError::Conflict => {
                    RuntimeProviderExecutionError::ApplicationConflict
                }
            })?;
        if receipt_digest == [0; 32] {
            return Err(RuntimeProviderExecutionError::ApplicationConflict);
        }
        self.acknowledge_terminal_output(recovered.record().outbox_id, receipt_digest)?;
        Ok(true)
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    fn current_key(&self) -> Result<ProviderJournalKeyBinding, RuntimeProviderExecutionError> {
        self.active_key
            .lock()
            .map_err(|_| RuntimeProviderExecutionError::PersistenceUnavailable)?
            .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    fn load_key(
        &self,
        binding: ProviderJournalKeyBinding,
    ) -> Result<ProviderJournalKeyMaterial, RuntimeProviderExecutionError> {
        self.keyring
            .load_provider_journal_key(secure_ref_from_binding(binding)?)
            .map_err(map_secure_store_error)
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    fn random_nonzero<const N: usize>(&self) -> Result<[u8; N], RuntimeProviderExecutionError> {
        loop {
            let mut bytes = [0_u8; N];
            self.random
                .fill(&mut bytes)
                .map_err(|_| RuntimeProviderExecutionError::JournalKeyUnavailable)?;
            if bytes != [0; N] {
                return Ok(bytes);
            }
        }
    }
}
impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    fn seal(
        &self,
        material: &ProviderJournalKeyMaterial,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<ProviderEncryptedPayload, RuntimeProviderExecutionError> {
        let nonce = self.random_nonzero::<12>()?;
        seal_payload_with_nonce(material, nonce, aad, plaintext)
    }
}
