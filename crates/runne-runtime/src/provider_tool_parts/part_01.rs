use core::fmt;

use runne_provider::{
    CancelRequest, ProviderFinishReason, ProviderPort, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamId, ProviderStreamValidator,
    ProviderTerminalDisposition, ProviderUsage, ScannerTerminalDisposition, StreamCursor,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::provider_execution::ProviderEventJournalContext;
use crate::provider_redaction::{PreJournalProviderEvent, ProviderEventRedaction};

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
