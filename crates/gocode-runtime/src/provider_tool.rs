use core::fmt;

use gocode_provider::{
    CancelRequest, ProviderFinishReason, ProviderPort, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamId, ProviderStreamValidator,
    ProviderTerminalDisposition, ProviderUsage, StreamCursor,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

/// Exact provider-requested tool call.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeToolCall {
    /// Provider-scoped call identity.
    pub call_id: String,
    /// Exact registered tool name.
    pub tool_name: String,
    /// Normalized JSON arguments.
    pub arguments_json: String,
}

impl fmt::Debug for RuntimeToolCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeToolCall")
            .field("call_id", &self.call_id)
            .field("tool_name", &self.tool_name)
            .field("arguments_json_len", &self.arguments_json.len())
            .finish()
    }
}

/// Persisted provider/tool transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderToolTransition {
    /// Cancellation intent was durable before signalling the adapter.
    CancellationIntent {
        /// Exact provider stream being cancelled.
        stream_id: ProviderStreamId,
    },
    /// Adapter acknowledged the local cancellation request.
    CancellationAcknowledged {
        /// Exact provider stream whose local cancellation was acknowledged.
        stream_id: ProviderStreamId,
    },
    /// Tool result was durable before provider continuation.
    ToolResult {
        /// Exact provider stream that requested the tool call.
        stream_id: ProviderStreamId,
        /// Provider-scoped tool call identity.
        call_id: String,
        /// Content-addressed result digest.
        result_digest: [u8; 32],
    },
    /// Ambiguous state freezes further effects.
    Frozen {
        /// Exact provider stream being fenced.
        stream_id: ProviderStreamId,
        /// Stable reason code.
        reason: &'static str,
    },
}

/// Exact durable disposition reconstructed before any provider/tool effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderToolRecoveryStatus {
    /// More provider events may be polled.
    Active,
    /// A terminal provider event is already durable.
    Terminal {
        /// Closed remote effect disposition.
        disposition: ProviderTerminalDisposition,
        /// Normalized terminal reason.
        reason: ProviderFinishReason,
    },
    /// A tool request is durable but its external effect is unresolved.
    ToolCallPending {
        /// Exact durable provider-requested tool call.
        call: RuntimeToolCall,
    },
    /// A tool result is already durable and can be returned idempotently.
    ToolResultReady {
        /// Provider-scoped call identity.
        call_id: String,
        /// Content-addressed result digest.
        result_digest: [u8; 32],
    },
    /// Cancellation intent is durable but adapter acknowledgement is unknown.
    CancellationPending,
    /// Local cancellation acknowledgement is durable.
    Cancelled,
    /// This stream was durably frozen.
    Frozen,
}

/// Runtime-owned durable prefix needed to resume one exact provider stream.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderToolRecoveryState {
    next_cursor: u64,
    text: String,
    usage: Option<ProviderUsage>,
    usage_unavailable: bool,
    status: ProviderToolRecoveryStatus,
}

impl fmt::Debug for ProviderToolRecoveryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderToolRecoveryState")
            .field("next_cursor", &self.next_cursor)
            .field("text_len", &self.text.len())
            .field("usage", &self.usage)
            .field("usage_unavailable", &self.usage_unavailable)
            .field("status", &self.status)
            .finish()
    }
}

impl ProviderToolRecoveryState {
    /// Constructs an active recovered prefix. Grammar consistency is checked
    /// by the pump.
    pub fn new(next_cursor: u64, text: String, usage: Option<ProviderUsage>) -> Self {
        Self::from_parts(
            next_cursor,
            text,
            usage,
            false,
            ProviderToolRecoveryStatus::Active,
        )
    }

    /// Constructs an exact recovered prefix and durable disposition.
    pub fn from_parts(
        next_cursor: u64,
        text: String,
        usage: Option<ProviderUsage>,
        usage_unavailable: bool,
        status: ProviderToolRecoveryStatus,
    ) -> Self {
        Self {
            next_cursor,
            text,
            usage,
            usage_unavailable,
            status,
        }
    }

    /// Returns the next unpersisted normalized event sequence.
    pub const fn next_cursor(&self) -> u64 {
        self.next_cursor
    }

    /// Returns the exact accumulated normalized text prefix.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns already persisted usage evidence, if any.
    pub const fn usage(&self) -> Option<ProviderUsage> {
        self.usage
    }

    /// Returns whether a closed remote terminal reported no exact usage.
    pub const fn usage_unavailable(&self) -> bool {
        self.usage_unavailable
    }

    /// Returns the exact durable stream/tool disposition.
    pub const fn status(&self) -> &ProviderToolRecoveryStatus {
        &self.status
    }
}

/// Durable transition journal required by the stream pump.
pub trait ProviderToolJournal: Send + Sync {
    /// Reconstructs the exact accepted stream prefix after restart.
    fn recovery_state(
        &self,
        stream_id: ProviderStreamId,
    ) -> Result<ProviderToolRecoveryState, ProviderToolLoopError>;
    /// Persists the complete bounded event for the exact stream before the
    /// adapter can be polled again.
    fn append_provider_event(
        &self,
        stream_id: ProviderStreamId,
        event: &ProviderStreamEvent,
    ) -> Result<(), ProviderToolLoopError>;
    /// Persists one recovery-significant transition.
    fn append(&self, transition: ProviderToolTransition) -> Result<(), ProviderToolLoopError>;
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
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderToolLoopOutcome {
    /// Provider completed normally with bounded text.
    Completed {
        /// Accumulated normalized text.
        text: String,
        /// Optional provider-reported normalized usage.
        usage: Option<ProviderUsage>,
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
    /// Provider returned an authenticated failed/incomplete terminal that may
    /// be settled without applying partial text to Conversation state.
    RemoteTerminal {
        /// Closed remote effect disposition.
        disposition: ProviderTerminalDisposition,
        /// Normalized terminal reason.
        reason: ProviderFinishReason,
        /// Bounded partial output retained only as recovery evidence.
        text: String,
        /// Exact provider usage, when supplied.
        usage: Option<ProviderUsage>,
        /// Whether the runtime must conservatively consume the full admitted
        /// reservation because exact usage was unavailable.
        usage_unavailable: bool,
    },
}

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
        let recovery = self.journal.recovery_state(stream_id)?;
        let mut cursor = recovery.next_cursor();
        let mut text = recovery.text().to_owned();
        let mut usage = recovery.usage();
        let mut usage_unavailable = recovery.usage_unavailable();
        if text.len() > self.max_text_bytes {
            return self.freeze(stream_id, "journal_text_bound");
        }
        if usage.is_some() && usage_unavailable {
            return self.freeze(stream_id, "provider_journal");
        }
        if recovery.next_cursor() == 0
            && matches!(
                recovery.status(),
                ProviderToolRecoveryStatus::Terminal { .. }
                    | ProviderToolRecoveryStatus::ToolCallPending { .. }
                    | ProviderToolRecoveryStatus::ToolResultReady { .. }
            )
        {
            return self.freeze(stream_id, "provider_journal");
        }
        match recovery.status() {
            ProviderToolRecoveryStatus::Active => {}
            ProviderToolRecoveryStatus::Terminal {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            } if !usage_unavailable => {
                return Ok(ProviderToolLoopOutcome::Completed { text, usage });
            }
            ProviderToolRecoveryStatus::Terminal {
                disposition,
                reason,
            } if valid_remote_terminal(disposition, reason)
                && (usage.is_some() || usage_unavailable) =>
            {
                return Ok(ProviderToolLoopOutcome::RemoteTerminal {
                    disposition: *disposition,
                    reason: reason.clone(),
                    text,
                    usage,
                    usage_unavailable,
                });
            }
            ProviderToolRecoveryStatus::Terminal { .. } => {
                return self.freeze(stream_id, "terminal_reason");
            }
            ProviderToolRecoveryStatus::ToolCallPending { .. }
            | ProviderToolRecoveryStatus::CancellationPending
            | ProviderToolRecoveryStatus::Frozen => {
                return Ok(ProviderToolLoopOutcome::Uncertain);
            }
            ProviderToolRecoveryStatus::ToolResultReady {
                call_id,
                result_digest,
            } => {
                return Ok(ProviderToolLoopOutcome::ToolResultReady {
                    call_id: call_id.clone(),
                    result_digest: *result_digest,
                });
            }
            ProviderToolRecoveryStatus::Cancelled => {
                return Ok(ProviderToolLoopOutcome::Cancelled);
            }
        }
        let mut validator = match ProviderStreamValidator::resume_at(
            cursor,
            usage.is_some() || usage_unavailable,
        ) {
            Ok(validator) => validator,
            Err(_) => return self.freeze(stream_id, "provider_journal"),
        };
        loop {
            let item = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    self.journal.append(ProviderToolTransition::CancellationIntent {
                        stream_id,
                    })?;
                    provider.cancel(CancelRequest::new(stream_id)).await
                        .map_err(|_| ProviderToolLoopError::ProviderFailed)?;
                    self.journal.append(
                        ProviderToolTransition::CancellationAcknowledged { stream_id }
                    )?;
                    return Ok(ProviderToolLoopOutcome::Cancelled);
                }
                item = provider.next(&stream_id, StreamCursor::new(cursor)) => item,
            };
            let item = match item {
                Ok(item) => item,
                Err(_) => return self.freeze(stream_id, "provider_stream"),
            };
            let event = item.event();
            if validator.accept(event).is_err() {
                return self.freeze(stream_id, "provider_grammar");
            }
            if let ProviderStreamEventKind::TextDelta { text: delta } = event.kind() {
                let next = text
                    .len()
                    .checked_add(delta.len())
                    .ok_or(ProviderToolLoopError::TextTooLarge)?;
                if next > self.max_text_bytes {
                    return self.freeze(stream_id, "text_bound");
                }
            }
            self.journal.append_provider_event(stream_id, event)?;
            cursor = cursor
                .checked_add(1)
                .ok_or(ProviderToolLoopError::MalformedStream)?;

            match event.kind() {
                ProviderStreamEventKind::Started => {}
                ProviderStreamEventKind::TextDelta { text: delta } => {
                    text.push_str(delta);
                }
                ProviderStreamEventKind::Usage { usage: event_usage } => {
                    if usage_unavailable || usage.replace(*event_usage).is_some() {
                        return self.freeze(stream_id, "duplicate_usage");
                    }
                }
                ProviderStreamEventKind::UsageUnavailable => {
                    if usage.is_some() || usage_unavailable {
                        return self.freeze(stream_id, "duplicate_usage");
                    }
                    usage_unavailable = true;
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
                                stream_id,
                                call_id: call.call_id.clone(),
                                result_digest,
                            })?;
                            return Ok(ProviderToolLoopOutcome::ToolResultReady {
                                call_id: call.call_id,
                                result_digest,
                            });
                        }
                        Ok(ToolHandoffDisposition::Uncertain) | Err(_) => {
                            return self.freeze(stream_id, "tool_effect");
                        }
                    }
                }
                ProviderStreamEventKind::Finished {
                    disposition: ProviderTerminalDisposition::Completed,
                    reason: ProviderFinishReason::Stop,
                } if !usage_unavailable => {
                    return Ok(ProviderToolLoopOutcome::Completed { text, usage });
                }
                ProviderStreamEventKind::Finished {
                    disposition,
                    reason,
                } if valid_remote_terminal(disposition, reason)
                    && (usage.is_some() || usage_unavailable) =>
                {
                    return Ok(ProviderToolLoopOutcome::RemoteTerminal {
                        disposition: *disposition,
                        reason: reason.clone(),
                        text,
                        usage,
                        usage_unavailable,
                    });
                }
                ProviderStreamEventKind::Finished { .. } => {
                    return self.freeze(stream_id, "terminal_reason");
                }
            }
        }
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
