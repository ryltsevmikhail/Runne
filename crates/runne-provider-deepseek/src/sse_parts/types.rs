use crate::decode_diagnostic::{
    DecodeTrace, DeepSeekDecodeDiagnostic, DeepSeekDecodeEventKind, DeepSeekDecodeField,
    DeepSeekDecodeIssue, DeepSeekDecodePhase, DeepSeekDecodeSchemaNode,
};
use thiserror::Error;

/// Sanitized fail-closed `DeepSeek` SSE parsing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeepSeekStreamError {
    /// SSE framing or JSON shape was malformed.
    #[error("DeepSeek stream event is malformed")]
    MalformedEvent,
    /// The event type is outside the exact text lifecycle allowlist.
    #[error("DeepSeek stream event type is unsupported")]
    UnknownEvent,
    /// Response/item/content identities or indexes did not remain exact.
    #[error("DeepSeek stream correlation does not match")]
    CorrelationMismatch,
    /// A lifecycle wrapper was missing, duplicated or out of order.
    #[error("DeepSeek stream lifecycle transition is invalid")]
    IllegalTransition,
    /// A frame, stream, event-count or normalized-text bound was exceeded.
    #[error("DeepSeek stream exceeded a configured bound")]
    StreamLimitExceeded,
    /// EOF arrived without one allowed terminal event.
    #[error("DeepSeek stream ended without terminal evidence")]
    TerminalMissing,
    /// A successful terminal omitted or contradicted usage evidence.
    #[error("DeepSeek completed response usage is invalid")]
    InvalidUsage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleStage {
    Start,
    Created,
    InProgress,
    ItemAdded,
    PartAdded,
    TextDone,
    PartDone,
    ItemDone,
    ToolItemAdded,
    ToolArgumentsDone,
    ToolItemDone,
    Terminal,
}
