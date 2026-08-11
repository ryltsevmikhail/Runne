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
        let pending = self
            .store
            .pending_terminal_outbox()
            .map_err(map_execution_error)?;
        for record in &pending {
            if self
                .redaction
                .terminal_disposition(record.attempt_id)
                .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
                != Some(gocode_provider::ScannerTerminalDisposition::Completed)
            {
                return Err(RuntimeProviderExecutionError::PolicyDenied);
            }
        }
        pending
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
