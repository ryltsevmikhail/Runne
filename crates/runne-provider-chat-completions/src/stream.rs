use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use thiserror::Error;

use crate::ChatCompletionsProfile;
use crate::stream_types::{Choice, Chunk};

const MAX_FRAME_BYTES: usize = 65_536;
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_EVENTS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 65_536;
/// Bounded Chat Completions SSE decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ChatCompletionsStreamError {
    /// The SSE framing or JSON payload was malformed.
    #[error("Chat Completions stream event malformed")]
    Malformed,
    /// A stream bound was exceeded.
    #[error("Chat Completions stream bound exceeded")]
    BoundExceeded,
    /// Stream ended without a terminal marker.
    #[error("Chat Completions stream terminal missing")]
    TerminalMissing,
    /// Usage evidence was malformed or inconsistent.
    #[error("Chat Completions usage invalid")]
    InvalidUsage,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StreamState {
    #[default]
    NotStarted,
    Active,
    Terminal,
    Finished,
}
impl StreamState {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal | Self::Finished)
    }
}
/// Incremental parser for the OpenAI-compatible text stream.
#[derive(Debug, Default)]
pub struct ChatCompletionsStreamDecoder {
    pending: Vec<u8>,
    frame: Vec<u8>,
    decoded: usize,
    events: usize,
    sequence: u64,
    state: StreamState,
    usage_seen: bool,
    terminal_disposition: Option<ProviderTerminalDisposition>,
    terminal_reason: Option<ProviderFinishReason>,
    output_bytes: usize,
    normalized: Vec<ProviderStreamEvent>,
    expected_model: Option<String>,
    response_id: Option<String>,
    require_identity: bool,
    frame_limit: Option<usize>,
}

impl ChatCompletionsStreamDecoder {
    /// Creates a decoder with no provider-specific response identity.
    ///
    /// Use [`Self::for_profile`] at a qualified dispatch boundary so model
    /// identity is checked against the immutable profile.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Creates a decoder bound to one exact profile response model.
    #[must_use]
    pub fn for_profile(profile: &ChatCompletionsProfile) -> Self {
        Self {
            expected_model: Some(profile.model_id().to_owned()),
            require_identity: true,
            frame_limit: Some(profile.max_frame_bytes()),
            ..Self::default()
        }
    }

    /// Pushes an arbitrary response fragment.
    ///
    /// # Errors
    /// Returns an error when framing, payloads, or stream bounds are invalid.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ChatCompletionsStreamError> {
        let frame_limit = self.frame_limit.unwrap_or(MAX_FRAME_BYTES);
        self.decoded = self
            .decoded
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_STREAM_BYTES)
            .ok_or(ChatCompletionsStreamError::BoundExceeded)?;
        self.pending.extend_from_slice(bytes);
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending.drain(..=index).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                self.dispatch_frame()?;
            } else if line.starts_with(b"data:") {
                let value = line.get(5..).unwrap_or_default();
                let value = value.strip_prefix(b" ").unwrap_or(value);
                self.frame.extend_from_slice(value);
                if self.frame.len() > frame_limit {
                    return Err(ChatCompletionsStreamError::BoundExceeded);
                }
            } else if !line.starts_with(b":") {
                return Err(ChatCompletionsStreamError::Malformed);
            }
        }
        if self.pending.len() > frame_limit {
            return Err(ChatCompletionsStreamError::BoundExceeded);
        }
        Ok(())
    }

    /// Completes decoding and returns ordered normalized events.
    ///
    /// # Errors
    /// Returns `TerminalMissing` when the stream has not ended with `[DONE]`.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, ChatCompletionsStreamError> {
        if !self.pending.is_empty() || !self.frame.is_empty() || self.state != StreamState::Finished
        {
            return Err(ChatCompletionsStreamError::TerminalMissing);
        }
        Ok(self.normalized)
    }

    fn dispatch_frame(&mut self) -> Result<(), ChatCompletionsStreamError> {
        if self.frame.is_empty() {
            return Ok(());
        }
        let frame = std::mem::take(&mut self.frame);
        self.events = self
            .events
            .checked_add(1)
            .filter(|n| *n <= MAX_EVENTS)
            .ok_or(ChatCompletionsStreamError::BoundExceeded)?;
        if self.state == StreamState::Finished {
            return Err(ChatCompletionsStreamError::Malformed);
        }
        if frame == b"[DONE]" {
            return self.finish_stream();
        }
        self.dispatch_chunk(&frame)
    }

    fn finish_stream(&mut self) -> Result<(), ChatCompletionsStreamError> {
        if !self.state.is_terminal() || self.state == StreamState::Finished {
            return Err(ChatCompletionsStreamError::Malformed);
        }
        if !self.usage_seen {
            self.push_kind(ProviderStreamEventKind::UsageUnavailable)?;
        }
        self.push_kind(ProviderStreamEventKind::Finished {
            disposition: self
                .terminal_disposition
                .ok_or(ChatCompletionsStreamError::Malformed)?,
            reason: self
                .terminal_reason
                .clone()
                .ok_or(ChatCompletionsStreamError::Malformed)?,
        })?;
        self.state = StreamState::Finished;
        Ok(())
    }

    fn dispatch_chunk(&mut self, frame: &[u8]) -> Result<(), ChatCompletionsStreamError> {
        let chunk: Chunk =
            serde_json::from_slice(frame).map_err(|_| ChatCompletionsStreamError::Malformed)?;
        if let Some(expected_model) = self.expected_model.as_ref()
            && chunk.model.as_deref() != Some(expected_model.as_str())
        {
            return Err(ChatCompletionsStreamError::Malformed);
        }
        if self.require_identity
            && self.state == StreamState::NotStarted
            && (chunk.id.is_none() || chunk.model.is_none())
        {
            return Err(ChatCompletionsStreamError::Malformed);
        }
        if let Some(id) = chunk.id {
            if let Some(previous) = self.response_id.as_deref() {
                if previous != id {
                    return Err(ChatCompletionsStreamError::Malformed);
                }
            } else {
                self.response_id = Some(id);
            }
        }
        if self.state.is_terminal()
            && chunk.choices.iter().any(|choice| {
                choice.delta.content.is_some()
                    || choice.delta.tool_calls.is_some()
                    || choice.finish_reason.is_some()
            })
        {
            return Err(ChatCompletionsStreamError::Malformed);
        }
        if self.state == StreamState::NotStarted {
            self.push_kind(ProviderStreamEventKind::Started)?;
            self.state = StreamState::Active;
        }
        if let Some(choice) = chunk.choices.first() {
            self.dispatch_choice(choice)?;
        }
        if let Some(usage) = chunk.usage {
            self.dispatch_usage(usage)?;
        }
        Ok(())
    }

    fn dispatch_choice(&mut self, choice: &Choice) -> Result<(), ChatCompletionsStreamError> {
        if choice.delta.tool_calls.is_some() {
            return Err(ChatCompletionsStreamError::Malformed);
        }
        if let Some(text) = choice.delta.content.as_deref() {
            self.output_bytes = self
                .output_bytes
                .checked_add(text.len())
                .filter(|n| *n <= MAX_TEXT_BYTES)
                .ok_or(ChatCompletionsStreamError::BoundExceeded)?;
            self.push_kind(ProviderStreamEventKind::TextDelta {
                text: text.to_owned(),
            })?;
        }
        if let Some(reason) = choice.finish_reason.as_deref() {
            if self.state.is_terminal() {
                return Err(ChatCompletionsStreamError::Malformed);
            }
            let (disposition, normalized_reason) = match reason {
                "stop" => (
                    ProviderTerminalDisposition::Completed,
                    ProviderFinishReason::Stop,
                ),
                "length" => (
                    ProviderTerminalDisposition::RemoteIncomplete,
                    ProviderFinishReason::Length,
                ),
                "content_filter" => (
                    ProviderTerminalDisposition::RemoteFailed,
                    ProviderFinishReason::ContentFilter,
                ),
                "tool_calls" | "function_call" => {
                    return Err(ChatCompletionsStreamError::Malformed);
                }
                _ => return Err(ChatCompletionsStreamError::Malformed),
            };
            self.terminal_disposition = Some(disposition);
            self.terminal_reason = Some(normalized_reason);
            self.state = StreamState::Terminal;
        }
        Ok(())
    }

    fn dispatch_usage(
        &mut self,
        usage: crate::stream_types::Usage,
    ) -> Result<(), ChatCompletionsStreamError> {
        if self.usage_seen {
            return Err(ChatCompletionsStreamError::InvalidUsage);
        }
        let normalized = ProviderUsage::new(
            usage.prompt_tokens,
            usage.completion_tokens,
            usage
                .prompt_tokens_details
                .map_or(0, |details| details.cached_tokens),
            usage
                .completion_tokens_details
                .map_or(0, |details| details.reasoning_tokens),
        )
        .map_err(|_| ChatCompletionsStreamError::InvalidUsage)?;
        if let Some(total_tokens) = usage.total_tokens
            && total_tokens != usage.prompt_tokens.saturating_add(usage.completion_tokens)
        {
            return Err(ChatCompletionsStreamError::InvalidUsage);
        }
        self.push_kind(ProviderStreamEventKind::Usage { usage: normalized })?;
        self.usage_seen = true;
        Ok(())
    }

    fn push_kind(
        &mut self,
        kind: ProviderStreamEventKind,
    ) -> Result<(), ChatCompletionsStreamError> {
        let event = ProviderStreamEvent::new(self.sequence, kind)
            .map_err(|_| ChatCompletionsStreamError::Malformed)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ChatCompletionsStreamError::BoundExceeded)?;
        self.normalized.push(event);
        Ok(())
    }
}
