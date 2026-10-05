/// Exact identity for recovering a D2 provider `Stop` terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderToolStopSelector {
    pub attempt_id: DispatchAttemptId,
    pub taskrun_id: runne_domain::id::TaskRunId,
    pub conversation_id: runne_domain::id::ConversationId,
    pub execution_attempt_id: runne_domain::id::AttemptId,
    pub principal_id: String,
    pub outbox_id: [u8; 16],
    pub terminal_sequence: u64,
    pub settlement_digest: [u8; 32],
    pub fencing_token: u64,
    pub call_digest_version: ProviderCallDigestVersion,
    pub profile_digest: [u8; 32],
    pub runtime_generation: u64,
}

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore
        + ProviderTerminalPersistence
        + runne_application::provider::ProviderRemoteRecoveryStore,
    P: ProviderTerminalPricing,
{
    /// Authenticates and decrypts one exact, accounted ToolProposal Stop.
    /// Generic text recovery deliberately continues to reject ToolProposal rows.
    pub fn recover_exact_tool_stop(
        &self,
        selector: ProviderToolStopSelector,
    ) -> Result<RecoveredProviderTerminalOutput, RuntimeProviderExecutionError> {
        let mut rows = self
            .store
            .pending_tool_proposal_outbox_for_attempt(selector.attempt_id)
            .map_err(map_execution_error)?
            .into_iter()
            .filter(|row| {
                row.outbox_id == selector.outbox_id
                    && row.terminal_sequence == selector.terminal_sequence
                    && row.settlement_digest == selector.settlement_digest
            });
        let record = rows
            .next()
            .ok_or(RuntimeProviderExecutionError::JournalCorrupt)?;
        if rows.next().is_some()
            || record.application_kind != ProviderTerminalApplicationKind::ToolProposal
            || record.attempt_id != selector.attempt_id
            || record.taskrun_id != selector.taskrun_id
            || record.conversation_id != selector.conversation_id
            || record.execution_attempt_id != selector.execution_attempt_id
            || record.principal_id != selector.principal_id
            || record.fencing_token != selector.fencing_token
            || record.call_digest_version != selector.call_digest_version
            || record.profile_digest != selector.profile_digest
            || record.runtime_generation != selector.runtime_generation
            || record.source
                != runne_application::provider::ProviderTerminalOutboxSource::StreamJournal
        {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        if self
            .redaction
            .terminal_disposition(record.attempt_id)
            .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
            != Some(runne_provider::ScannerTerminalDisposition::Completed)
        {
            return Err(RuntimeProviderExecutionError::PolicyDenied);
        }
        let journal = self
            .store
            .load_encrypted_events(record.attempt_id)
            .map_err(map_execution_error)?;
        let (events, keys) = self.decrypt_terminal_journal(&journal)?;
        let assembled = assemble_tool_terminal_stream(&events)?;
        if journal.iter().any(|event| {
            event.call_digest_version != record.call_digest_version
                || event.profile_digest != record.profile_digest
                || event.runtime_generation != record.runtime_generation
        }) {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let stop = matches!(
            events.last().map(ProviderStreamEvent::kind),
            Some(
                ProviderStreamEventKind::ScannerCompleted {
                    reason: ProviderFinishReason::Stop,
                    ..
                } | ProviderStreamEventKind::Finished {
                    reason: ProviderFinishReason::Stop,
                    ..
                }
            )
        );
        if !stop
            || assembled.disposition != ProviderTerminalDisposition::Completed
            || assembled.terminal_sequence != selector.terminal_sequence
            || journal.iter().filter(|event| event.terminal).count() != 1
        {
            return Err(RuntimeProviderExecutionError::TerminalRejected);
        }
        match self.prohibited_content.inspect(
            CanonicalContentBoundary::CanonicalMutation,
            assembled.output.as_slice(),
        ) {
            Ok(ContentDisposition::Allowed { .. }) => {}
            _ => return Err(RuntimeProviderExecutionError::PolicyDenied),
        }
        let usage = assembled
            .usage
            .exact()
            .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
        let pricing = self
            .store
            .load_terminal_pricing_binding(record.attempt_id)
            .map_err(map_execution_error)?;
        let priced = self
            .pricing
            .price_terminal_usage(
                pricing.pricing_revision_digest(),
                &record.profile_digest,
                pricing.effect_started_at(),
                usage,
            )
            .map_err(|_| RuntimeProviderExecutionError::TerminalRejected)?;
        if priced.currency() != pricing.currency()
            || priced.charge_micros() > pricing.reserved_cost_micros()
        {
            return Err(RuntimeProviderExecutionError::TerminalRejected);
        }
        let context = ProviderEventJournalContext {
            attempt_id: record.attempt_id,
            fencing_token: record.fencing_token,
            call_digest_version: record.call_digest_version,
            profile_digest: record.profile_digest,
            runtime_generation: record.runtime_generation,
        };
        let expected_settlement = application_settlement_digest(
            ProviderTerminalApplicationKind::ToolProposal,
            settlement_digest(
                &context,
                &pricing,
                selector.terminal_sequence,
                assembled.output.as_slice(),
                usage,
                false,
                ProviderTerminalDisposition::Completed,
                priced.charge_micros(),
                priced.currency(),
            ),
        );
        if expected_settlement != selector.settlement_digest {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let terminal = journal
            .iter()
            .find(|event| event.sequence == selector.terminal_sequence && event.terminal)
            .ok_or(RuntimeProviderExecutionError::JournalCorrupt)?;
        if terminal.key != record.key
            || terminal.call_digest_version != record.call_digest_version
            || terminal.profile_digest != record.profile_digest
            || terminal.runtime_generation != record.runtime_generation
        {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        let material = keys
            .iter()
            .find(|(key, _)| *key == terminal.key)
            .map(|(_, material)| material)
            .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)?;
        let aad = outbox_aad(
            &context,
            record.key,
            selector.terminal_sequence,
            selector.outbox_id,
        );
        let output = Zeroizing::new(open_payload(material, &aad, &record.encrypted_output)?);
        if output.as_slice() != assembled.output.as_slice() {
            return Err(RuntimeProviderExecutionError::JournalCorrupt);
        }
        Ok(RecoveredProviderTerminalOutput { record, output })
    }
}
