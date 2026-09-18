mod anthropic;
mod common;
mod gemini;

use runne_provider::ProviderStreamEvent;
use thiserror::Error;

use crate::{AnthropicMessagesProfile, GeminiProfile, sse::SseError};
use common::{State, WireDecodeError};

const DEFAULT_FRAME_BYTES: usize = 65_536;

/// Anthropic stream decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AnthropicStreamError {
    /// SSE or JSON shape is malformed.
    #[error("Anthropic stream event is malformed")]
    Malformed,
    /// A bound was exceeded.
    #[error("Anthropic stream bound exceeded")]
    BoundExceeded,
    /// The lifecycle ended before `message_stop`.
    #[error("Anthropic stream terminal is missing")]
    TerminalMissing,
    /// Usage was absent or mathematically inconsistent.
    #[error("Anthropic stream usage is invalid")]
    InvalidUsage,
    /// A tool, image, or other unsupported block appeared.
    #[error("Anthropic stream content is not text-only")]
    UnsupportedContent,
}

/// Gemini stream decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GeminiStreamError {
    /// SSE or JSON shape is malformed.
    #[error("Gemini stream event is malformed")]
    Malformed,
    /// A bound was exceeded.
    #[error("Gemini stream bound exceeded")]
    BoundExceeded,
    /// The lifecycle ended before a finish reason.
    #[error("Gemini stream terminal is missing")]
    TerminalMissing,
    /// Usage was absent or mathematically inconsistent.
    #[error("Gemini stream usage is invalid")]
    InvalidUsage,
    /// A function call, image or another non-text part appeared.
    #[error("Gemini stream content is not text-only")]
    UnsupportedContent,
}

/// Incremental Anthropic Messages SSE decoder.
#[derive(Debug)]
pub struct AnthropicStreamDecoder {
    state: State,
}

impl Default for AnthropicStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl AnthropicStreamDecoder {
    /// Creates an identity-unbound decoder for fixture parsing.
    pub fn new() -> Self {
        Self {
            state: State::new(DEFAULT_FRAME_BYTES, None, None),
        }
    }
    /// Creates a decoder requiring the exact profile model in `message_start`.
    pub fn for_profile(profile: &AnthropicMessagesProfile) -> Self {
        Self {
            state: State::new(
                profile.limits().max_frame_bytes(),
                Some(profile.model_id()),
                profile.model_version_alias(),
            ),
        }
    }
    /// Accepts an arbitrary response-body fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), AnthropicStreamError> {
        let frames = self.state.framer.push(bytes).map_err(map_anthropic_sse)?;
        for frame in frames {
            anthropic::accept(&mut self.state, frame).map_err(map_anthropic_wire)?;
        }
        Ok(())
    }
    /// Closes the decoder and returns normalized ordered events.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, AnthropicStreamError> {
        self.state.framer.finish().map_err(map_anthropic_sse)?;
        if !self.state.terminal {
            return Err(AnthropicStreamError::TerminalMissing);
        }
        Ok(self.state.normalized)
    }
}

/// Incremental Gemini `streamGenerateContent` SSE decoder.
#[derive(Debug)]
pub struct GeminiStreamDecoder {
    state: State,
}

impl Default for GeminiStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GeminiStreamDecoder {
    /// Creates an identity-unbound decoder for fixture parsing.
    pub fn new() -> Self {
        Self {
            state: State::new(DEFAULT_FRAME_BYTES, None, None),
        }
    }
    /// Creates a decoder requiring the exact `modelVersion` identity.
    pub fn for_profile(profile: &GeminiProfile) -> Self {
        Self {
            state: State::new(
                profile.limits().max_frame_bytes(),
                Some(profile.model_id()),
                profile.model_version_alias(),
            ),
        }
    }
    /// Accepts an arbitrary response-body fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), GeminiStreamError> {
        let frames = self.state.framer.push(bytes).map_err(map_gemini_sse)?;
        for frame in frames {
            gemini::accept(&mut self.state, frame).map_err(map_gemini_wire)?;
        }
        Ok(())
    }
    /// Closes the decoder and returns normalized ordered events.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, GeminiStreamError> {
        self.state.framer.finish().map_err(map_gemini_sse)?;
        if !self.state.terminal {
            return Err(GeminiStreamError::TerminalMissing);
        }
        Ok(self.state.normalized)
    }
}

const fn map_anthropic_sse(error: SseError) -> AnthropicStreamError {
    match error {
        SseError::BoundExceeded => AnthropicStreamError::BoundExceeded,
        SseError::Truncated => AnthropicStreamError::TerminalMissing,
        SseError::Malformed => AnthropicStreamError::Malformed,
    }
}
const fn map_gemini_sse(error: SseError) -> GeminiStreamError {
    match error {
        SseError::BoundExceeded => GeminiStreamError::BoundExceeded,
        SseError::Truncated => GeminiStreamError::TerminalMissing,
        SseError::Malformed => GeminiStreamError::Malformed,
    }
}
const fn map_anthropic_wire(error: WireDecodeError) -> AnthropicStreamError {
    match error {
        WireDecodeError::BoundExceeded => AnthropicStreamError::BoundExceeded,
        WireDecodeError::InvalidUsage => AnthropicStreamError::InvalidUsage,
        WireDecodeError::UnsupportedContent => AnthropicStreamError::UnsupportedContent,
        WireDecodeError::Malformed => AnthropicStreamError::Malformed,
    }
}
const fn map_gemini_wire(error: WireDecodeError) -> GeminiStreamError {
    match error {
        WireDecodeError::BoundExceeded => GeminiStreamError::BoundExceeded,
        WireDecodeError::InvalidUsage => GeminiStreamError::InvalidUsage,
        WireDecodeError::UnsupportedContent => GeminiStreamError::UnsupportedContent,
        WireDecodeError::Malformed => GeminiStreamError::Malformed,
    }
}
