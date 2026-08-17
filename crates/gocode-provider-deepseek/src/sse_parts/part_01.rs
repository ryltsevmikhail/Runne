use std::collections::BTreeSet;

use gocode_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    DEEPSEEK_MAX_DECODED_STREAM_BYTES, DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES, DEEPSEEK_MAX_SSE_EVENTS,
    DEEPSEEK_MAX_SSE_FRAME_BYTES, DEEPSEEK_MAX_SSE_LINES, DEEPSEEK_REQUEST_MODEL, DEEPSEEK_SERVICE_TIER,
};

const MAX_REMOTE_IDENTIFIER_BYTES: usize = 256;
const MAX_REMOTE_DIAGNOSTIC_BYTES: usize = 4096;

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
    Terminal,
}

#[derive(Debug)]
struct Lifecycle {
    stage: LifecycleStage,
    response_id: Option<String>,
    item_id: Option<String>,
    text: String,
    normalized: Vec<ProviderStreamEvent>,
    next_remote_sequence: u64,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            stage: LifecycleStage::Start,
            response_id: None,
            item_id: None,
            text: String::new(),
            normalized: Vec::new(),
            next_remote_sequence: 0,
        }
    }
}

/// Incremental bounded SSE decoder for the exact Responses text lifecycle.
#[derive(Debug, Default)]
pub struct DeepSeekSseDecoder {
    pending: Vec<u8>,
    event_name: Option<String>,
    data_lines: Vec<String>,
    frame_bytes: usize,
    decoded_bytes: usize,
    event_count: usize,
    line_count: usize,
    lifecycle: Lifecycle,
}

impl DeepSeekSseDecoder {
    /// Adds one arbitrary response-body fragment.
    ///
    /// Fragment boundaries may split CRLF, JSON and UTF-8 code points.
    ///
    /// # Errors
    ///
    /// Returns a sanitized closed error when framing or any bound fails.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), DeepSeekStreamError> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= DEEPSEEK_MAX_DECODED_STREAM_BYTES)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        self.pending
            .try_reserve(bytes.len())
            .map_err(|_| DeepSeekStreamError::StreamLimitExceeded)?;
        self.pending.extend_from_slice(bytes);
        let mut consumed = 0usize;
        while let Some(position) = self.pending[consumed..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let line_end = consumed
                .checked_add(position)
                .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
            let wire_bytes = position
                .checked_add(1)
                .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
            let mut line = self.pending[consumed..line_end].to_vec();
            consumed = line_end
                .checked_add(1)
                .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.accept_line(&line, wire_bytes)?;
        }
        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        if self.pending.len() > DEEPSEEK_MAX_SSE_FRAME_BYTES {
            return Err(DeepSeekStreamError::StreamLimitExceeded);
        }
        Ok(())
    }

    /// Closes the decoder and returns provider-neutral ordered evidence.
    ///
    /// # Errors
    ///
    /// Requires a blank-frame-delimited terminal event and no trailing bytes.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, DeepSeekStreamError> {
        if !self.pending.is_empty()
            || self.event_name.is_some()
            || !self.data_lines.is_empty()
            || self.lifecycle.stage != LifecycleStage::Terminal
        {
            return Err(DeepSeekStreamError::TerminalMissing);
        }
        Ok(self.lifecycle.normalized)
    }

    fn accept_line(&mut self, line: &[u8], wire_bytes: usize) -> Result<(), DeepSeekStreamError> {
        self.line_count = self
            .line_count
            .checked_add(1)
            .filter(|count| *count <= DEEPSEEK_MAX_SSE_LINES)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        self.frame_bytes = self
            .frame_bytes
            .checked_add(wire_bytes)
            .filter(|total| *total <= DEEPSEEK_MAX_SSE_FRAME_BYTES)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        if line.is_empty() {
            self.dispatch_frame()?;
            self.frame_bytes = 0;
            return Ok(());
        }
        let line = std::str::from_utf8(line).map_err(|_| DeepSeekStreamError::MalformedEvent)?;
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = line
            .split_once(':')
            .ok_or(DeepSeekStreamError::MalformedEvent)?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if self.event_name.is_none() && !value.is_empty() => {
                self.event_name = Some(value.to_owned());
            }
            "data" => self.data_lines.push(value.to_owned()),
            _ => return Err(DeepSeekStreamError::MalformedEvent),
        }
        Ok(())
    }

    fn dispatch_frame(&mut self) -> Result<(), DeepSeekStreamError> {
        if self.event_name.is_none() && self.data_lines.is_empty() {
            return Ok(());
        }
        let event_name = self
            .event_name
            .take()
            .ok_or(DeepSeekStreamError::MalformedEvent)?;
        if self.data_lines.is_empty() {
            return Err(DeepSeekStreamError::MalformedEvent);
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        self.event_count = self
            .event_count
            .checked_add(1)
            .filter(|count| *count <= DEEPSEEK_MAX_SSE_EVENTS)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        let value: Value =
            serde_json::from_str(&data).map_err(|_| DeepSeekStreamError::MalformedEvent)?;
        self.lifecycle.accept(&event_name, &value)
    }
}

impl Lifecycle {
    fn accept(&mut self, event_name: &str, value: &Value) -> Result<(), DeepSeekStreamError> {
        if self.stage == LifecycleStage::Terminal {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let object = value.as_object().ok_or(DeepSeekStreamError::MalformedEvent)?;
        let event_type = required_string(object, "type")?;
        if event_type != event_name {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        let sequence = required_u64(object, "sequence_number")?;
        if sequence != self.next_remote_sequence {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        self.next_remote_sequence = self
            .next_remote_sequence
            .checked_add(1)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        match event_type {
            "response.created" => self.accept_created(object),
            "response.in_progress" => self.accept_in_progress(object),
            "response.output_item.added" => self.accept_item_added(object),
            "response.content_part.added" => self.accept_part_added(object),
            "response.output_text.delta" => self.accept_text_delta(object),
            "response.output_text.done" => self.accept_text_done(object),
            "response.content_part.done" => self.accept_part_done(object),
            "response.output_item.done" => self.accept_item_done(object),
            "response.completed" => self.accept_completed(object),
            "response.failed" => self.accept_failed(object),
            "response.incomplete" => self.accept_incomplete(object),
            "error" => self.accept_error(object),
            _ => Err(DeepSeekStreamError::UnknownEvent),
        }
    }

}
impl Lifecycle {
    fn accept_created(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::Start {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "in_progress")?;
        require_empty_output(response)?;
        require_null_or_missing(response, "usage")?;
        self.ensure_started()?;
        self.stage = LifecycleStage::Created;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_in_progress(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::Created {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "in_progress")?;
        require_empty_output(response)?;
        require_null_or_missing(response, "usage")?;
        self.stage = LifecycleStage::InProgress;
        Ok(())
    }

}
