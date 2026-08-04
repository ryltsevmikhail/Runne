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
    /// Provider reached a closed remote terminal without billable usage
    /// evidence. Runtime settlement must conservatively consume the admitted
    /// maximum reservation and must not infer zero usage.
    UsageUnavailable,
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
            Self::UsageUnavailable => formatter.write_str("UsageUnavailable"),
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
    UsageUnavailable,
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
