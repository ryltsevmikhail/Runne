type DecryptedTerminalJournal = (
    Vec<ProviderStreamEvent>,
    Vec<(ProviderJournalKeyBinding, ProviderJournalKeyMaterial)>,
);
type DecryptedTerminalJournalResult =
    Result<DecryptedTerminalJournal, RuntimeProviderExecutionError>;

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    fn decrypt_terminal_journal(
        &self,
        records: &[ProviderJournalAppendRequest],
    ) -> DecryptedTerminalJournalResult {
        let mut keys = Vec::new();
        for record in records {
            if !keys.iter().any(|(binding, _)| *binding == record.key) {
                keys.push((record.key, self.load_key(record.key)?));
            }
        }
        let events = decrypt_unknown_snapshot(records, &keys).map_err(map_execution_error)?;
        Ok((events, keys))
    }

    fn commit_unknown_terminal(
        &self,
        context: &ProviderEventJournalContext,
        records: &[ProviderJournalAppendRequest],
        keys: &[(ProviderJournalKeyBinding, ProviderJournalKeyMaterial)],
        assembled: &AssembledTerminal,
        usage: Option<ProviderUsage>,
        reason: ProviderUnknownAccountingReason,
    ) -> Result<ProviderTerminalCommitOutcome, RuntimeProviderExecutionError> {
        let terminal = records
            .iter()
            .find(|record| record.sequence == assembled.terminal_sequence && record.terminal)
            .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
        if terminal.attempt_id != context.attempt_id
            || terminal.fencing_token != context.fencing_token
            || terminal.call_digest_version != context.call_digest_version
            || terminal.profile_digest != context.profile_digest
            || terminal.runtime_generation != context.runtime_generation
        {
            return Err(RuntimeProviderExecutionError::TerminalRejected);
        }
        let selector = ProviderTerminalUnknownSelector::new(
            context.attempt_id,
            assembled.terminal_sequence,
            context.fencing_token,
        );
        let outbox_id = stable_outbox_id(context, assembled.terminal_sequence);
        let encrypted_output = if assembled.disposition == ProviderTerminalDisposition::Completed {
            let material = keys
                .iter()
                .find(|(binding, _)| *binding == terminal.key)
                .map(|(_, material)| material)
                .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)?;
            let aad = outbox_aad(
                context,
                terminal.key,
                assembled.terminal_sequence,
                outbox_id,
            );
            Some(self.seal(material, &aad, &assembled.output)?)
        } else {
            None
        };
        let authenticator = RuntimeUnknownAuthenticator {
            selector,
            context: *context,
            journal_digest: journal_records_digest(records),
            keys,
            reason: Some(reason),
            disposition: assembled.disposition,
            usage,
            output: encrypted_output,
            outbox_id,
        };
        self.store
            .commit_unknown_terminal(&selector, &authenticator)
            .map_err(map_execution_error)
    }

    fn replay_unknown_terminal(
        &self,
        context: &ProviderEventJournalContext,
        records: &[ProviderJournalAppendRequest],
        keys: &[(ProviderJournalKeyBinding, ProviderJournalKeyMaterial)],
        assembled: &AssembledTerminal,
    ) -> Result<Option<ProviderTerminalCommitOutcome>, RuntimeProviderExecutionError> {
        let selector = ProviderTerminalUnknownSelector::new(
            context.attempt_id,
            assembled.terminal_sequence,
            context.fencing_token,
        );
        let authenticator = RuntimeUnknownAuthenticator {
            selector,
            context: *context,
            journal_digest: journal_records_digest(records),
            keys,
            reason: None,
            disposition: assembled.disposition,
            usage: assembled.usage.exact(),
            output: None,
            outbox_id: stable_outbox_id(context, assembled.terminal_sequence),
        };
        self.store
            .replay_unknown_terminal(&selector, &authenticator)
            .map_err(map_execution_error)
    }
}
