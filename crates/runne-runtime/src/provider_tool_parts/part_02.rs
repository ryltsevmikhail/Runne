impl fmt::Debug for ProviderToolLoopOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed { text, usage } => formatter
                .debug_struct("Completed")
                .field("text_len", &text.len())
                .field("usage", usage)
                .finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::ToolResultReady {
                call_id,
                result_digest,
            } => formatter
                .debug_struct("ToolResultReady")
                .field("call_id", call_id)
                .field("result_digest", result_digest)
                .finish(),
            Self::Uncertain => formatter.write_str("Uncertain"),
            Self::RemoteTerminal {
                disposition,
                reason,
                text,
                usage,
                usage_unavailable,
            } => formatter
                .debug_struct("RemoteTerminal")
                .field("disposition", disposition)
                .field("reason", reason)
                .field("text_len", &text.len())
                .field("usage", usage)
                .field("usage_unavailable", usage_unavailable)
                .finish(),
        }
    }
}
/// Provider/tool loop failure before or during durable transition handling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderToolLoopError {
    /// Journal read/write failed.
    #[error("provider/tool journal unavailable")]
    JournalUnavailable,
    /// Provider stream or control operation failed.
    #[error("provider stream failed")]
    ProviderFailed,
    /// Text exceeded the configured bound.
    #[error("provider text exceeded its bound")]
    TextTooLarge,
    /// Provider emitted a terminal/tool sequence that cannot be interpreted.
    #[error("malformed provider stream")]
    MalformedStream,
    /// Tool handoff failed before a trustworthy disposition.
    #[error("tool handoff failed")]
    ToolHandoffFailed,
}

/// Runtime-owned supervised provider/tool loop.
pub struct ProviderToolLoop<'a, J, T> {
    journal: J,
    tool_handoff: T,
    max_text_bytes: usize,
    redaction: &'a dyn ProviderEventRedaction,
    journal_context: ProviderEventJournalContext,
}
