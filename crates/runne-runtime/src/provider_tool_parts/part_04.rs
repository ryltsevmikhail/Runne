const MAX_PROVIDER_TOOL_EVENTS: u64 = 512;
const MAX_TOOL_PROPOSAL_ARGUMENT_BYTES: usize = 8 * 1024;
const TOOL_RESPONSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

impl<'a, J, T> ProviderToolLoop<'a, J, T>
where
    J: ProviderToolJournal,
{
    fn scanner_completed(&self) -> bool {
        matches!(
            self.redaction
                .terminal_disposition(self.journal_context.attempt_id),
            Ok(Some(ScannerTerminalDisposition::Completed))
        )
    }

    fn freeze(
        &self,
        stream_id: ProviderStreamId,
        reason: &'static str,
    ) -> Result<ProviderToolLoopOutcome, ProviderToolLoopError> {
        self.journal
            .append(ProviderToolTransition::Frozen { stream_id, reason })?;
        Ok(ProviderToolLoopOutcome::Uncertain)
    }
}

fn valid_remote_terminal(
    disposition: &ProviderTerminalDisposition,
    reason: &ProviderFinishReason,
) -> bool {
    matches!(
        (disposition, reason),
        (
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error
        ) | (
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length
                | ProviderFinishReason::ContentFilter
                | ProviderFinishReason::Error
        )
    )
}
