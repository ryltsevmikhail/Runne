use gocode_provider::{
    CancelRequest, ProviderFinishReason, ProviderPort, ProviderStreamEventKind, ProviderStreamId,
    StreamCursor,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Persisted provider/tool transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderToolTransition {
    /// One exact provider event was persisted.
    ProviderEvent {
        /// Event sequence.
        sequence: u64,
        /// Stable event category.
        kind: &'static str,
    },
    /// Cancellation intent was durable before signalling the adapter.
    CancellationIntent,
    /// Tool result was durable before provider continuation.
    ToolResult {
        /// Provider-scoped tool call identity.
        call_id: String,
        /// Content-addressed result digest.
        result_digest: [u8; 32],
    },
    /// Ambiguous state freezes further effects.
    Frozen {
        /// Stable reason code.
        reason: &'static str,
    },
}

/// Durable transition journal required by the stream pump.
pub trait ProviderToolJournal: Send + Sync {
    /// Returns the next unpersisted provider sequence after restart.
    fn next_cursor(&self, stream_id: ProviderStreamId) -> Result<u64, ProviderToolLoopError>;
    /// Persists one recovery-significant transition.
    fn append(&self, transition: ProviderToolTransition) -> Result<(), ProviderToolLoopError>;
}

/// Exact provider-requested tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeToolCall {
    /// Provider-scoped call identity.
    pub call_id: String,
    /// Exact registered tool name.
    pub tool_name: String,
    /// Normalized JSON arguments.
    pub arguments_json: String,
}

/// Tool handoff result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolHandoffDisposition {
    /// Tool completed and produced a content-addressed result.
    Completed {
        /// Exact result digest.
        result_digest: [u8; 32],
    },
    /// Tool external state is ambiguous.
    Uncertain,
}

/// Runtime-owned handoff into ToolGateway.
pub trait ToolCallHandoffPort: Send + Sync {
    /// Dispatches one already-persisted provider tool request.
    fn dispatch(
        &self,
        call: &RuntimeToolCall,
    ) -> Result<ToolHandoffDisposition, ProviderToolLoopError>;
}

/// Supervised provider/tool pump outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderToolLoopOutcome {
    /// Provider completed normally with bounded text.
    Completed {
        /// Accumulated normalized text.
        text: String,
    },
    /// Cancellation was persisted and signalled.
    Cancelled,
    /// Tool result was persisted and provider continuation may be constructed.
    ToolResultReady {
        /// Provider-scoped tool call identity.
        call_id: String,
        /// Exact result digest.
        result_digest: [u8; 32],
    },
    /// Further effects are frozen pending reconciliation.
    Uncertain,
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
pub struct ProviderToolLoop<J, T> {
    journal: J,
    tool_handoff: T,
    max_text_bytes: usize,
}

impl<J, T> ProviderToolLoop<J, T>
where
    J: ProviderToolJournal,
    T: ToolCallHandoffPort,
{
    /// Constructs a pump with a non-zero text bound.
    pub fn new(
        journal: J,
        tool_handoff: T,
        max_text_bytes: usize,
    ) -> Result<Self, ProviderToolLoopError> {
        if max_text_bytes == 0 {
            return Err(ProviderToolLoopError::TextTooLarge);
        }
        Ok(Self {
            journal,
            tool_handoff,
            max_text_bytes,
        })
    }

    /// Polls one stream until terminal, tool handoff, cancellation or uncertainty.
    pub async fn run<P: ProviderPort>(
        &self,
        provider: &P,
        stream_id: ProviderStreamId,
        cancellation: &CancellationToken,
    ) -> Result<ProviderToolLoopOutcome, ProviderToolLoopError> {
        let mut cursor = self.journal.next_cursor(stream_id)?;
        let mut text = String::new();
        loop {
            let item = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    self.journal.append(ProviderToolTransition::CancellationIntent)?;
                    provider.cancel(CancelRequest::new(stream_id)).await
                        .map_err(|_| ProviderToolLoopError::ProviderFailed)?;
                    return Ok(ProviderToolLoopOutcome::Cancelled);
                }
                item = provider.next(&stream_id, StreamCursor::new(cursor)) => item,
            };
            let item = match item {
                Ok(item) => item,
                Err(_) => return self.freeze("provider_stream"),
            };
            let event = item.event();
            let kind_name = event_kind_name(event.kind());
            self.journal.append(ProviderToolTransition::ProviderEvent {
                sequence: event.sequence(),
                kind: kind_name,
            })?;
            cursor = cursor
                .checked_add(1)
                .ok_or(ProviderToolLoopError::MalformedStream)?;

            match event.kind() {
                ProviderStreamEventKind::Started => {}
                ProviderStreamEventKind::TextDelta { text: delta } => {
                    let next = text
                        .len()
                        .checked_add(delta.len())
                        .ok_or(ProviderToolLoopError::TextTooLarge)?;
                    if next > self.max_text_bytes {
                        return self.freeze("text_bound");
                    }
                    text.push_str(delta);
                }
                ProviderStreamEventKind::ToolCallRequested {
                    call_id,
                    tool_name,
                    arguments_json,
                } => {
                    let call = RuntimeToolCall {
                        call_id: call_id.clone(),
                        tool_name: tool_name.clone(),
                        arguments_json: arguments_json.clone(),
                    };
                    match self.tool_handoff.dispatch(&call) {
                        Ok(ToolHandoffDisposition::Completed { result_digest }) => {
                            self.journal.append(ProviderToolTransition::ToolResult {
                                call_id: call.call_id.clone(),
                                result_digest,
                            })?;
                            return Ok(ProviderToolLoopOutcome::ToolResultReady {
                                call_id: call.call_id,
                                result_digest,
                            });
                        }
                        Ok(ToolHandoffDisposition::Uncertain) | Err(_) => {
                            return self.freeze("tool_effect");
                        }
                    }
                }
                ProviderStreamEventKind::Finished {
                    reason: ProviderFinishReason::Stop,
                } => {
                    return Ok(ProviderToolLoopOutcome::Completed { text });
                }
                ProviderStreamEventKind::Finished { .. } => {
                    return self.freeze("terminal_reason");
                }
            }
        }
    }

    fn freeze(
        &self,
        reason: &'static str,
    ) -> Result<ProviderToolLoopOutcome, ProviderToolLoopError> {
        self.journal
            .append(ProviderToolTransition::Frozen { reason })?;
        Ok(ProviderToolLoopOutcome::Uncertain)
    }
}

fn event_kind_name(kind: &ProviderStreamEventKind) -> &'static str {
    match kind {
        ProviderStreamEventKind::Started => "started",
        ProviderStreamEventKind::TextDelta { .. } => "text_delta",
        ProviderStreamEventKind::ToolCallRequested { .. } => "tool_call_requested",
        ProviderStreamEventKind::Finished { .. } => "finished",
    }
}
