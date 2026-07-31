use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProviderFinishReason;

/// Provider-neutral terminal disposition of one external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTerminalDisposition {
    /// Provider completed the requested response.
    Completed,
    /// Provider returned an explicit failed terminal.
    RemoteFailed,
    /// Provider returned an explicit incomplete terminal.
    RemoteIncomplete,
    /// Local cancellation leaves remote settlement ambiguous.
    CancelledUncertain,
}

/// Maximum accepted normalized token count for one input or output category.
pub const MAX_PROVIDER_USAGE_TOKENS: u64 = 1_000_000_000;
/// Maximum accepted bytes in one normalized text delta.
pub const MAX_PROVIDER_TEXT_DELTA_BYTES: usize = 65_536;
/// Maximum accepted bytes in a provider tool-call identity or tool name.
pub const MAX_PROVIDER_TOOL_IDENTIFIER_BYTES: usize = 256;
/// Maximum accepted bytes in one normalized tool arguments JSON value.
pub const MAX_PROVIDER_TOOL_ARGUMENT_BYTES: usize = 262_144;

/// Invalid normalized provider usage evidence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderUsageError {
    /// Cached input tokens cannot exceed total input tokens.
    #[error("cached input tokens exceed input tokens")]
    CachedInputExceedsInput,
    /// Reasoning output tokens cannot exceed total output tokens.
    #[error("reasoning output tokens exceed output tokens")]
    ReasoningOutputExceedsOutput,
    /// Input and output token counts overflowed their checked aggregate.
    #[error("provider usage token total overflow")]
    TotalOverflow,
    /// A normalized token category exceeded the contract bound.
    #[error("provider usage token count exceeds {max} (actual {actual})")]
    TokenCountTooLarge {
        /// Maximum accepted category value.
        max: u64,
        /// Actual category value.
        actual: u64,
    },
}

/// Validated normalized token usage for one provider effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProviderUsage {
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    reasoning_output_tokens: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderUsage {
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    reasoning_output_tokens: u64,
}

impl<'de> Deserialize<'de> for ProviderUsage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderUsage::deserialize(deserializer)?;
        Self::new(
            raw.input_tokens,
            raw.output_tokens,
            raw.cached_input_tokens,
            raw.reasoning_output_tokens,
        )
        .map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ProviderUsage {
    /// Constructs internally consistent usage evidence.
    pub fn new(
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        reasoning_output_tokens: u64,
    ) -> Result<Self, ProviderUsageError> {
        for actual in [input_tokens, output_tokens] {
            if actual > MAX_PROVIDER_USAGE_TOKENS {
                return Err(ProviderUsageError::TokenCountTooLarge {
                    max: MAX_PROVIDER_USAGE_TOKENS,
                    actual,
                });
            }
        }
        if cached_input_tokens > input_tokens {
            return Err(ProviderUsageError::CachedInputExceedsInput);
        }
        if reasoning_output_tokens > output_tokens {
            return Err(ProviderUsageError::ReasoningOutputExceedsOutput);
        }
        input_tokens
            .checked_add(output_tokens)
            .ok_or(ProviderUsageError::TotalOverflow)?;
        Ok(Self {
            input_tokens,
            output_tokens,
            cached_input_tokens,
            reasoning_output_tokens,
        })
    }

    /// Returns total billed input tokens.
    pub const fn input_tokens(self) -> u64 {
        self.input_tokens
    }

    /// Returns total billed output tokens.
    pub const fn output_tokens(self) -> u64 {
        self.output_tokens
    }

    /// Returns cached tokens included in `input_tokens`.
    pub const fn cached_input_tokens(self) -> u64 {
        self.cached_input_tokens
    }

    /// Returns reasoning tokens included in `output_tokens`.
    pub const fn reasoning_output_tokens(self) -> u64 {
        self.reasoning_output_tokens
    }

    /// Returns the checked input plus output token total.
    pub const fn total_tokens(self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

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
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderStreamEventKind {
    /// Stream started.
    Started,
    /// Incremental text output.
    TextDelta {
        /// Bounded normalized text.
        text: String,
    },
    /// Validated token usage for the exact provider effect.
    Usage {
        /// Provider-neutral usage evidence.
        usage: ProviderUsage,
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
        /// Closed terminal effect disposition.
        disposition: ProviderTerminalDisposition,
        /// Normalized reason.
        reason: ProviderFinishReason,
    },
}

impl fmt::Debug for ProviderStreamEventKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started => formatter.write_str("Started"),
            Self::TextDelta { text } => formatter
                .debug_struct("TextDelta")
                .field("text_len", &text.len())
                .finish(),
            Self::Usage { usage } => formatter
                .debug_struct("Usage")
                .field("usage", usage)
                .finish(),
            Self::ToolCallRequested {
                call_id,
                tool_name,
                arguments_json,
            } => formatter
                .debug_struct("ToolCallRequested")
                .field("call_id", call_id)
                .field("tool_name", tool_name)
                .field("arguments_json_len", &arguments_json.len())
                .finish(),
            Self::Finished {
                disposition,
                reason,
            } => formatter
                .debug_struct("Finished")
                .field("disposition", disposition)
                .field("reason", reason)
                .finish(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawProviderStreamEventTag {
    Started,
    TextDelta,
    Usage,
    ToolCallRequested,
    Finished,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderStreamEventKind {
    kind: RawProviderStreamEventTag,
    text: Option<String>,
    usage: Option<ProviderUsage>,
    call_id: Option<String>,
    tool_name: Option<String>,
    arguments_json: Option<String>,
    disposition: Option<ProviderTerminalDisposition>,
    reason: Option<ProviderFinishReason>,
}

impl<'de> Deserialize<'de> for ProviderStreamEventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderStreamEventKind::deserialize(deserializer)?;
        let no_text = raw.text.is_none();
        let no_usage = raw.usage.is_none();
        let no_tool =
            raw.call_id.is_none() && raw.tool_name.is_none() && raw.arguments_json.is_none();
        let no_terminal = raw.disposition.is_none() && raw.reason.is_none();
        let kind = match raw.kind {
            RawProviderStreamEventTag::Started if no_text && no_usage && no_tool && no_terminal => {
                Self::Started
            }
            RawProviderStreamEventTag::TextDelta
                if raw.text.is_some() && no_usage && no_tool && no_terminal =>
            {
                Self::TextDelta {
                    text: raw.text.expect("guarded text"),
                }
            }
            RawProviderStreamEventTag::Usage
                if no_text && raw.usage.is_some() && no_tool && no_terminal =>
            {
                Self::Usage {
                    usage: raw.usage.expect("guarded usage"),
                }
            }
            RawProviderStreamEventTag::ToolCallRequested
                if no_text
                    && no_usage
                    && raw.call_id.is_some()
                    && raw.tool_name.is_some()
                    && raw.arguments_json.is_some()
                    && no_terminal =>
            {
                Self::ToolCallRequested {
                    call_id: raw.call_id.expect("guarded call id"),
                    tool_name: raw.tool_name.expect("guarded tool name"),
                    arguments_json: raw.arguments_json.expect("guarded arguments"),
                }
            }
            RawProviderStreamEventTag::Finished
                if no_text
                    && no_usage
                    && no_tool
                    && raw.disposition.is_some()
                    && raw.reason.is_some() =>
            {
                Self::Finished {
                    disposition: raw.disposition.expect("guarded disposition"),
                    reason: raw.reason.expect("guarded reason"),
                }
            }
            _ => {
                return Err(<D::Error as serde::de::Error>::custom(
                    "provider stream event payload does not match its kind",
                ));
            }
        };
        validate_event_kind(&kind).map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(kind)
    }
}

/// One ordered normalized provider stream event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderStreamEvent {
    sequence: u64,
    kind: ProviderStreamEventKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderStreamEvent {
    sequence: u64,
    kind: ProviderStreamEventKind,
}

impl<'de> Deserialize<'de> for ProviderStreamEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawProviderStreamEvent::deserialize(deserializer)?;
        Self::new(raw.sequence, raw.kind).map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl ProviderStreamEvent {
    /// Constructs an event. Sequence continuity is validated by the stream.
    pub fn new(sequence: u64, kind: ProviderStreamEventKind) -> Result<Self, StreamError> {
        validate_event_kind(&kind)?;
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
    pub fn from_event(event: ProviderStreamEvent) -> Result<Self, StreamError> {
        validate_event_kind(event.kind())?;
        Ok(Self { event })
    }

    /// Returns the normalized event.
    pub const fn event(&self) -> &ProviderStreamEvent {
        &self.event
    }
}

/// Stateful validator for one ordered normalized provider stream.
#[derive(Debug, Clone, Default)]
pub struct ProviderStreamValidator {
    next_sequence: u64,
    started: bool,
    usage_seen: bool,
    terminal: bool,
}

impl ProviderStreamValidator {
    /// Reconstructs the exact grammar state from a runtime-owned durable cursor.
    ///
    /// A non-zero cursor proves that the already accepted event at sequence zero
    /// was `Started`; callers must persist only events accepted by this validator.
    pub fn resume_at(next_sequence: u64, usage_seen: bool) -> Result<Self, StreamError> {
        if next_sequence == 0 && usage_seen {
            return Err(StreamError::InvalidResumeState);
        }
        Ok(Self {
            next_sequence,
            started: next_sequence > 0,
            usage_seen,
            terminal: false,
        })
    }

    /// Accepts exactly one next event or returns a closed grammar error.
    pub fn accept(&mut self, event: &ProviderStreamEvent) -> Result<(), StreamError> {
        if event.sequence() != self.next_sequence {
            return Err(StreamError::InvalidScriptSequence {
                expected: self.next_sequence,
                actual: event.sequence(),
            });
        }
        if self.terminal {
            return Err(StreamError::EventAfterTerminal);
        }
        match event.kind() {
            ProviderStreamEventKind::Started if self.started => {
                return Err(StreamError::DuplicateStarted);
            }
            ProviderStreamEventKind::Started => self.started = true,
            _ if !self.started => return Err(StreamError::EventBeforeStarted),
            ProviderStreamEventKind::Usage { .. } if self.usage_seen => {
                return Err(StreamError::DuplicateUsage);
            }
            ProviderStreamEventKind::Usage { .. } => self.usage_seen = true,
            ProviderStreamEventKind::Finished { .. } => self.terminal = true,
            ProviderStreamEventKind::TextDelta { .. }
            | ProviderStreamEventKind::ToolCallRequested { .. } => {}
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StreamError::SequenceOverflow)?;
        Ok(())
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
    /// A non-start event appeared before the stream start marker.
    #[error("provider stream event appeared before start")]
    EventBeforeStarted,
    /// A stream emitted its start marker more than once.
    #[error("provider stream emitted duplicate start")]
    DuplicateStarted,
    /// Usage evidence appeared more than once.
    #[error("provider stream emitted duplicate usage")]
    DuplicateUsage,
    /// Any event appeared after terminal evidence.
    #[error("provider stream emitted event after terminal")]
    EventAfterTerminal,
    /// Durable recovery metadata cannot represent a valid accepted prefix.
    #[error("provider stream recovery state is invalid")]
    InvalidResumeState,
    /// Event sequencing exceeded the supported cursor space.
    #[error("provider stream sequence overflow")]
    SequenceOverflow,
    /// A normalized provider payload was empty where content is required.
    #[error("provider stream payload is empty")]
    EmptyPayload,
    /// One normalized provider payload exceeded its byte bound.
    #[error("provider stream payload exceeds {max} bytes (actual {actual})")]
    PayloadTooLarge {
        /// Maximum accepted bytes.
        max: usize,
        /// Actual bytes.
        actual: usize,
    },
    /// Provider tool identity contained unsupported characters.
    #[error("provider tool identity is invalid")]
    InvalidToolIdentifier,
    /// Provider tool arguments were not one valid JSON value.
    #[error("provider tool arguments JSON is invalid")]
    InvalidToolArguments,
}

fn validate_event_kind(kind: &ProviderStreamEventKind) -> Result<(), StreamError> {
    match kind {
        ProviderStreamEventKind::TextDelta { text } => {
            validate_payload_bytes(text, MAX_PROVIDER_TEXT_DELTA_BYTES, false)
        }
        ProviderStreamEventKind::ToolCallRequested {
            call_id,
            tool_name,
            arguments_json,
        } => {
            for identifier in [call_id, tool_name] {
                validate_payload_bytes(identifier, MAX_PROVIDER_TOOL_IDENTIFIER_BYTES, false)?;
                if !identifier.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Err(StreamError::InvalidToolIdentifier);
                }
            }
            validate_payload_bytes(arguments_json, MAX_PROVIDER_TOOL_ARGUMENT_BYTES, false)?;
            serde_json::from_str::<serde_json::Value>(arguments_json)
                .map_err(|_| StreamError::InvalidToolArguments)?;
            Ok(())
        }
        ProviderStreamEventKind::Started
        | ProviderStreamEventKind::Usage { .. }
        | ProviderStreamEventKind::Finished { .. } => Ok(()),
    }
}

fn validate_payload_bytes(value: &str, max: usize, allow_empty: bool) -> Result<(), StreamError> {
    if !allow_empty && value.is_empty() {
        return Err(StreamError::EmptyPayload);
    }
    if value.len() > max {
        return Err(StreamError::PayloadTooLarge {
            max,
            actual: value.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_fails_closed_when_sequence_space_is_exhausted() {
        let mut validator = ProviderStreamValidator {
            next_sequence: u64::MAX,
            started: true,
            usage_seen: false,
            terminal: false,
        };
        let event = ProviderStreamEvent::new(
            u64::MAX,
            ProviderStreamEventKind::TextDelta {
                text: "bounded".to_owned(),
            },
        )
        .unwrap();

        assert_eq!(validator.accept(&event), Err(StreamError::SequenceOverflow));
    }
}
