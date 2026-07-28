use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProviderFinishReason;

/// Cursor of the next expected normalized stream event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamCursor(u64);

impl StreamCursor {
    /// Constructs a cursor for an exact event sequence.
    pub const fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    /// Returns the expected event sequence.
    pub const fn sequence(self) -> u64 {
        self.0
    }
}

/// Normalized provider stream event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderStreamEventKind {
    /// Stream started.
    Started,
    /// Incremental text output.
    TextDelta {
        /// Bounded normalized text.
        text: String,
    },
    /// Provider requested one exact tool invocation.
    ToolCallRequested {
        /// Provider-scoped call identity.
        call_id: String,
        /// Exact registered tool identity.
        tool_name: String,
        /// Normalized JSON arguments.
        arguments_json: String,
    },
    /// Terminal provider reason.
    Finished {
        /// Normalized reason.
        reason: ProviderFinishReason,
    },
}

/// One ordered normalized provider stream event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStreamEvent {
    sequence: u64,
    kind: ProviderStreamEventKind,
}

impl ProviderStreamEvent {
    /// Constructs an event. Sequence continuity is validated by the stream.
    pub const fn new(sequence: u64, kind: ProviderStreamEventKind) -> Result<Self, StreamError> {
        Ok(Self { sequence, kind })
    }

    /// Returns the event sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the normalized payload.
    pub const fn kind(&self) -> &ProviderStreamEventKind {
        &self.kind
    }
}

/// Item returned by the normalized stream boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStreamItem {
    event: ProviderStreamEvent,
}

impl ProviderStreamItem {
    pub(crate) const fn new(event: ProviderStreamEvent) -> Self {
        Self { event }
    }

    /// Constructs an item from an already normalized adapter event.
    pub const fn from_event(event: ProviderStreamEvent) -> Result<Self, StreamError> {
        Ok(Self { event })
    }

    /// Returns the normalized event.
    pub const fn event(&self) -> &ProviderStreamEvent {
        &self.event
    }
}

/// Fail-closed normalized stream error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StreamError {
    /// The requested stream does not exist.
    #[error("provider stream was not found")]
    NotFound,
    /// Cursor skipped an expected event.
    #[error("provider stream sequence gap: expected={expected}, actual={actual}")]
    SequenceGap {
        /// Next expected sequence.
        expected: u64,
        /// Requested sequence.
        actual: u64,
    },
    /// No further event exists.
    #[error("provider stream is closed")]
    Closed,
    /// The provider returned an unknown terminal reason.
    #[error("unknown provider finish reason: {raw}")]
    UnknownFinishReason {
        /// Bounded raw reason.
        raw: String,
    },
    /// Test/conformance script violated ordered sequencing.
    #[error("invalid scripted stream sequence: expected={expected}, actual={actual}")]
    InvalidScriptSequence {
        /// Expected sequence.
        expected: u64,
        /// Actual sequence.
        actual: u64,
    },
}
