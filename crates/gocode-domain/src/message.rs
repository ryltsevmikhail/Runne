//! Durable text-only Conversation message values.

use crate::id::{AttemptId, MessageId, TaskRunId};

/// Maximum UTF-8 byte length of one durable text message.
pub const MAX_MESSAGE_TEXT_BYTES: usize = 64 * 1024;

/// Closed validation failures for canonical message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageTextError {
    /// Empty messages are not accepted.
    Empty,
    /// The UTF-8 representation exceeded [`MAX_MESSAGE_TEXT_BYTES`].
    TooLarge {
        /// Maximum accepted byte length.
        max: usize,
        /// Actual UTF-8 byte length.
        actual: usize,
    },
}

/// Validated, bounded UTF-8 message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageText(String);

impl MessageText {
    /// Validates and constructs canonical message text.
    pub fn new(value: impl Into<String>) -> Result<Self, MessageTextError> {
        let value = value.into();
        if value.is_empty() {
            return Err(MessageTextError::Empty);
        }
        if value.len() > MAX_MESSAGE_TEXT_BYTES {
            return Err(MessageTextError::TooLarge {
                max: MAX_MESSAGE_TEXT_BYTES,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the value and returns its text.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Closed role set for the first canonical text-only message contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    /// Text supplied by the authenticated caller.
    User,
    /// Text produced by the bound execution attempt.
    Assistant,
}

impl MessageRole {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

/// Durable message reconstructed from a Conversation event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMessage {
    /// Message identity.
    pub message_id: MessageId,
    /// User or assistant role.
    pub role: MessageRole,
    /// TaskRun coordinating this user/assistant exchange.
    pub taskrun_id: TaskRunId,
    /// Exact execution attempt that owns the exchange.
    pub attempt_id: AttemptId,
    /// Validated text.
    pub text: MessageText,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_text_is_non_empty_and_bounded_by_utf8_bytes() {
        assert_eq!(MessageText::new(""), Err(MessageTextError::Empty));
        assert!(MessageText::new("x".repeat(MAX_MESSAGE_TEXT_BYTES)).is_ok());
        assert_eq!(
            MessageText::new("x".repeat(MAX_MESSAGE_TEXT_BYTES + 1)),
            Err(MessageTextError::TooLarge {
                max: MAX_MESSAGE_TEXT_BYTES,
                actual: MAX_MESSAGE_TEXT_BYTES + 1,
            })
        );
        assert_eq!(
            MessageText::new("я".repeat(MAX_MESSAGE_TEXT_BYTES / 2))
                .unwrap()
                .as_str()
                .len(),
            MAX_MESSAGE_TEXT_BYTES
        );
    }
}
