use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamValidator,
};
use thiserror::Error;

const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;

/// Safe evidence summary from a normalized text-only provider stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEvidence {
    event_count: usize,
    text_delta_count: usize,
    text_bytes: usize,
    usage_available: bool,
}

impl StreamEvidence {
    /// Number of accepted normalized events.
    #[must_use]
    pub const fn event_count(self) -> usize {
        self.event_count
    }
    /// Number of accepted text fragments.
    #[must_use]
    pub const fn text_delta_count(self) -> usize {
        self.text_delta_count
    }
    /// Total UTF-8 bytes across text fragments.
    #[must_use]
    pub const fn text_bytes(self) -> usize {
        self.text_bytes
    }
    /// Whether validated billable usage was present.
    #[must_use]
    pub const fn usage_available(self) -> bool {
        self.usage_available
    }
}

/// Text-only stream conformance failure without provider payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StreamContractError {
    /// No normalized event was supplied.
    #[error("provider stream is empty")]
    Empty,
    /// The public normalized grammar rejected the event sequence.
    #[error("provider stream ordering is invalid")]
    InvalidOrder,
    /// A non-text normalized event appeared in a text-only stream.
    #[error("provider stream contains an unsupported event")]
    UnsupportedEvent,
    /// The stream ended without a terminal event.
    #[error("provider stream has no terminal event")]
    MissingTerminal,
    /// The text fragments did not equal the expected deterministic text.
    #[error("provider stream text does not match the expected text")]
    TextMismatch,
    /// The stream exceeded the local text bound.
    #[error("provider stream text exceeds the conformance bound")]
    TextTooLarge,
    /// A successful stream omitted validated usage evidence.
    #[error("provider stream has no usage evidence")]
    UsageMissing,
    /// The provider supplied an unknown terminal reason.
    #[error("provider stream has an unknown terminal reason")]
    UnknownFinishReason,
}

/// Validates ordered text fragments, usage policy, and terminal closure.
///
/// # Errors
///
/// Returns [`StreamContractError`] when normalized ordering, text-only shape,
/// usage policy, or terminal closure is violated.
pub fn validate_text_stream(
    events: &[ProviderStreamEvent],
    expected_text: &str,
    require_usage: bool,
) -> Result<StreamEvidence, StreamContractError> {
    if events.is_empty() {
        return Err(StreamContractError::Empty);
    }
    let mut validator = ProviderStreamValidator::default();
    let mut text = String::new();
    let mut text_delta_count = 0;
    let mut text_bytes: usize = 0;
    let mut usage_available = false;
    let mut terminal = false;
    for event in events {
        validator
            .accept(event)
            .map_err(|_| StreamContractError::InvalidOrder)?;
        match event.kind() {
            ProviderStreamEventKind::Started | ProviderStreamEventKind::UsageUnavailable => {}
            ProviderStreamEventKind::TextDelta { text: delta } => {
                text_bytes = text_bytes
                    .checked_add(delta.len())
                    .ok_or(StreamContractError::TextTooLarge)?;
                if text_bytes > MAX_TEXT_BYTES {
                    return Err(StreamContractError::TextTooLarge);
                }
                text.push_str(delta);
                text_delta_count += 1;
            }
            ProviderStreamEventKind::Usage { .. } => usage_available = true,
            ProviderStreamEventKind::Finished { reason, .. } => {
                if matches!(reason, ProviderFinishReason::Unknown { .. }) {
                    return Err(StreamContractError::UnknownFinishReason);
                }
                terminal = true;
            }
            _ => return Err(StreamContractError::UnsupportedEvent),
        }
    }
    if !terminal {
        return Err(StreamContractError::MissingTerminal);
    }
    if text != expected_text {
        return Err(StreamContractError::TextMismatch);
    }
    if require_usage && !usage_available {
        return Err(StreamContractError::UsageMissing);
    }
    Ok(StreamEvidence {
        event_count: events.len(),
        text_delta_count,
        text_bytes,
        usage_available,
    })
}
