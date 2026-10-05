use runne_provider::ScannerTerminalDisposition;

impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Polls through the canonical commit-before-next-poll path, then gives
    /// only that committed normalized event to the bounded tool proposal
    /// collector. Collection never polls or appends provider events itself.
    pub async fn next_and_commit_tool_aware<A: ProviderPort + ?Sized>(
        &self,
        provider: &A,
        stream_id: &ProviderStreamId,
        cursor: StreamCursor,
        context: &ProviderEventJournalContext,
        collector: &mut crate::provider_tool::CommittedToolProposalCollector,
    ) -> Result<
        (
            ProviderStreamItem,
            Option<crate::provider_tool::ProviderToolLoopOutcome>,
        ),
        RuntimeProviderExecutionError,
    > {
        let item = self
            .next_and_commit(provider, stream_id, cursor, context)
            .await?;
        let scanner_completed = self
            .redaction
            .terminal_disposition(context.attempt_id)
            .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
            == Some(ScannerTerminalDisposition::Completed);
        let outcome = match collector.accept_committed(item.event(), scanner_completed) {
            Ok(outcome) => outcome,
            Err(_) => {
                let persisted = self
                    .store
                    .mark_execution_uncertain(context.attempt_id, context.fencing_token);
                cancel_uncommitted_stream(provider, *stream_id).await;
                persisted.map_err(|_| RuntimeProviderExecutionError::JournalCommitLost)?;
                return Err(RuntimeProviderExecutionError::TerminalRejected);
            }
        };
        Ok((item, outcome))
    }
}
