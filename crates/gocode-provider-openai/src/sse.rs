use std::collections::BTreeSet;

use gocode_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    OPENAI_MAX_DECODED_STREAM_BYTES, OPENAI_MAX_NORMALIZED_TEXT_BYTES, OPENAI_MAX_SSE_EVENTS,
    OPENAI_MAX_SSE_FRAME_BYTES, OPENAI_MAX_SSE_LINES, OPENAI_MAX_TRANSPORT_CHUNKS,
    OPENAI_REQUEST_MODEL, OPENAI_SERVICE_TIER, OpenAiTransportResponse,
};

const MAX_REMOTE_IDENTIFIER_BYTES: usize = 256;
const MAX_REMOTE_DIAGNOSTIC_BYTES: usize = 4096;

/// Sanitized fail-closed `OpenAI` SSE parsing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenAiStreamError {
    /// SSE framing or JSON shape was malformed.
    #[error("OpenAI stream event is malformed")]
    MalformedEvent,
    /// The event type is outside the exact text lifecycle allowlist.
    #[error("OpenAI stream event type is unsupported")]
    UnknownEvent,
    /// Response/item/content identities or indexes did not remain exact.
    #[error("OpenAI stream correlation does not match")]
    CorrelationMismatch,
    /// A lifecycle wrapper was missing, duplicated or out of order.
    #[error("OpenAI stream lifecycle transition is invalid")]
    IllegalTransition,
    /// A frame, stream, event-count or normalized-text bound was exceeded.
    #[error("OpenAI stream exceeded a configured bound")]
    StreamLimitExceeded,
    /// EOF arrived without one allowed terminal event.
    #[error("OpenAI stream ended without terminal evidence")]
    TerminalMissing,
    /// A successful terminal omitted or contradicted usage evidence.
    #[error("OpenAI completed response usage is invalid")]
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
pub struct OpenAiSseDecoder {
    pending: Vec<u8>,
    event_name: Option<String>,
    data_lines: Vec<String>,
    frame_bytes: usize,
    decoded_bytes: usize,
    event_count: usize,
    line_count: usize,
    lifecycle: Lifecycle,
}

impl OpenAiSseDecoder {
    /// Adds one arbitrary response-body fragment.
    ///
    /// Fragment boundaries may split CRLF, JSON and UTF-8 code points.
    ///
    /// # Errors
    ///
    /// Returns a sanitized closed error when framing or any bound fails.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), OpenAiStreamError> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= OPENAI_MAX_DECODED_STREAM_BYTES)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        self.pending
            .try_reserve(bytes.len())
            .map_err(|_| OpenAiStreamError::StreamLimitExceeded)?;
        self.pending.extend_from_slice(bytes);
        let mut consumed = 0usize;
        while let Some(position) = self.pending[consumed..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let line_end = consumed
                .checked_add(position)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            let wire_bytes = position
                .checked_add(1)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            let mut line = self.pending[consumed..line_end].to_vec();
            consumed = line_end
                .checked_add(1)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.accept_line(&line, wire_bytes)?;
        }
        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        if self.pending.len() > OPENAI_MAX_SSE_FRAME_BYTES {
            return Err(OpenAiStreamError::StreamLimitExceeded);
        }
        Ok(())
    }

    /// Closes the decoder and returns provider-neutral ordered evidence.
    ///
    /// # Errors
    ///
    /// Requires a blank-frame-delimited terminal event and no trailing bytes.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, OpenAiStreamError> {
        if !self.pending.is_empty()
            || self.event_name.is_some()
            || !self.data_lines.is_empty()
            || self.lifecycle.stage != LifecycleStage::Terminal
        {
            return Err(OpenAiStreamError::TerminalMissing);
        }
        Ok(self.lifecycle.normalized)
    }

    fn accept_line(&mut self, line: &[u8], wire_bytes: usize) -> Result<(), OpenAiStreamError> {
        self.line_count = self
            .line_count
            .checked_add(1)
            .filter(|count| *count <= OPENAI_MAX_SSE_LINES)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        self.frame_bytes = self
            .frame_bytes
            .checked_add(wire_bytes)
            .filter(|total| *total <= OPENAI_MAX_SSE_FRAME_BYTES)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        if line.is_empty() {
            self.dispatch_frame()?;
            self.frame_bytes = 0;
            return Ok(());
        }
        let line = std::str::from_utf8(line).map_err(|_| OpenAiStreamError::MalformedEvent)?;
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = line
            .split_once(':')
            .ok_or(OpenAiStreamError::MalformedEvent)?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if self.event_name.is_none() && !value.is_empty() => {
                self.event_name = Some(value.to_owned());
            }
            "data" => self.data_lines.push(value.to_owned()),
            _ => return Err(OpenAiStreamError::MalformedEvent),
        }
        Ok(())
    }

    fn dispatch_frame(&mut self) -> Result<(), OpenAiStreamError> {
        if self.event_name.is_none() && self.data_lines.is_empty() {
            return Ok(());
        }
        let event_name = self
            .event_name
            .take()
            .ok_or(OpenAiStreamError::MalformedEvent)?;
        if self.data_lines.is_empty() {
            return Err(OpenAiStreamError::MalformedEvent);
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        self.event_count = self
            .event_count
            .checked_add(1)
            .filter(|count| *count <= OPENAI_MAX_SSE_EVENTS)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        let value: Value =
            serde_json::from_str(&data).map_err(|_| OpenAiStreamError::MalformedEvent)?;
        self.lifecycle.accept(&event_name, &value)
    }
}

impl Lifecycle {
    fn accept(&mut self, event_name: &str, value: &Value) -> Result<(), OpenAiStreamError> {
        if self.stage == LifecycleStage::Terminal {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let object = value.as_object().ok_or(OpenAiStreamError::MalformedEvent)?;
        let event_type = required_string(object, "type")?;
        if event_type != event_name {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        let sequence = required_u64(object, "sequence_number")?;
        if sequence != self.next_remote_sequence {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        self.next_remote_sequence = self
            .next_remote_sequence
            .checked_add(1)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
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
            _ => Err(OpenAiStreamError::UnknownEvent),
        }
    }

    fn accept_created(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::Start {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "in_progress")?;
        require_empty_output(response)?;
        require_null_or_missing(response, "usage")?;
        self.ensure_started()?;
        self.stage = LifecycleStage::Created;
        Ok(())
    }

    fn accept_in_progress(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::Created {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "in_progress")?;
        require_empty_output(response)?;
        require_null_or_missing(response, "usage")?;
        self.stage = LifecycleStage::InProgress;
        Ok(())
    }

    fn accept_item_added(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["item", "output_index", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::InProgress || required_u64(event, "output_index")? != 0 {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let item = required_object(event, "item")?;
        validate_added_item(item)?;
        let item_id = required_string(item, "id")?;
        validate_identifier(item_id)?;
        self.item_id = Some(item_id.to_owned());
        self.stage = LifecycleStage::ItemAdded;
        Ok(())
    }

    fn accept_part_added(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(
            event,
            &[
                "content_index",
                "item_id",
                "output_index",
                "part",
                "sequence_number",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::ItemAdded {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_part(required_object(event, "part")?, "", true)?;
        self.stage = LifecycleStage::PartAdded;
        Ok(())
    }

    fn accept_text_delta(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys_subset(
            event,
            &[
                "content_index",
                "delta",
                "item_id",
                "logprobs",
                "output_index",
                "sequence_number",
                "type",
            ],
            &[
                "content_index",
                "delta",
                "item_id",
                "output_index",
                "sequence_number",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::PartAdded {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_empty_logprobs(event)?;
        let delta = required_string(event, "delta")?;
        if delta.is_empty() {
            return Err(OpenAiStreamError::MalformedEvent);
        }
        let next = self
            .text
            .len()
            .checked_add(delta.len())
            .filter(|length| *length <= OPENAI_MAX_NORMALIZED_TEXT_BYTES)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        self.text.reserve(next - self.text.len());
        self.text.push_str(delta);
        self.push_normalized(ProviderStreamEventKind::TextDelta {
            text: delta.to_owned(),
        })
    }

    fn accept_text_done(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys_subset(
            event,
            &[
                "content_index",
                "item_id",
                "logprobs",
                "output_index",
                "sequence_number",
                "text",
                "type",
            ],
            &[
                "content_index",
                "item_id",
                "output_index",
                "sequence_number",
                "text",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::PartAdded {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_empty_logprobs(event)?;
        if required_string(event, "text")? != self.text {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        self.stage = LifecycleStage::TextDone;
        Ok(())
    }

    fn accept_part_done(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(
            event,
            &[
                "content_index",
                "item_id",
                "output_index",
                "part",
                "sequence_number",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::TextDone {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_part(required_object(event, "part")?, &self.text, false)?;
        self.stage = LifecycleStage::PartDone;
        Ok(())
    }

    fn accept_item_done(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["item", "output_index", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::PartDone || required_u64(event, "output_index")? != 0 {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        validate_completed_item(
            required_object(event, "item")?,
            self.item_id()?,
            &self.text,
            "completed",
        )?;
        self.stage = LifecycleStage::ItemDone;
        Ok(())
    }

    fn accept_completed(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::ItemDone {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "completed")?;
        validate_terminal_response_guards(response, false, false)?;
        validate_output(response, self.item_id()?, &self.text, "completed", false)?;
        let usage_value = response
            .get("usage")
            .filter(|value| !value.is_null())
            .ok_or(OpenAiStreamError::InvalidUsage)?;
        let usage = parse_usage(usage_value)?;
        self.push_normalized(ProviderStreamEventKind::Usage { usage })?;
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

    fn accept_failed(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        self.ensure_terminal_prefix_allowed()?;
        let response = required_object(event, "response")?;
        self.bind_response(response, "failed")?;
        validate_terminal_response_guards(response, true, false)?;
        self.accept_optional_terminal_output(response, &["failed", "incomplete"])?;
        self.push_optional_usage(response)?;
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

    fn accept_incomplete(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        self.ensure_terminal_prefix_allowed()?;
        let response = required_object(event, "response")?;
        self.bind_response(response, "incomplete")?;
        validate_terminal_response_guards(response, false, true)?;
        self.accept_optional_terminal_output(response, &["incomplete"])?;
        self.push_optional_usage(response)?;
        let reason = match response
            .get("incomplete_details")
            .and_then(Value::as_object)
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str)
        {
            Some("max_output_tokens") => ProviderFinishReason::Length,
            Some("content_filter") => ProviderFinishReason::ContentFilter,
            Some(_) | None => ProviderFinishReason::Error,
        };
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteIncomplete,
            reason,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

    fn accept_error(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(
            event,
            &["code", "message", "param", "sequence_number", "type"],
        )?;
        if self.stage != LifecycleStage::Start {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        validate_diagnostic_string(event, "code")?;
        validate_diagnostic_string(event, "message")?;
        if event.get("param").is_none() {
            return Err(OpenAiStreamError::MalformedEvent);
        }
        self.ensure_started()?;
        self.push_normalized(ProviderStreamEventKind::UsageUnavailable)?;
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

    fn bind_response(
        &mut self,
        response: &Map<String, Value>,
        expected_status: &str,
    ) -> Result<(), OpenAiStreamError> {
        validate_response_guards(response)?;
        let response_id = required_string(response, "id")?;
        validate_identifier(response_id)?;
        match self.response_id.as_deref() {
            Some(existing) if existing != response_id => {
                return Err(OpenAiStreamError::CorrelationMismatch);
            }
            None => self.response_id = Some(response_id.to_owned()),
            Some(_) => {}
        }
        if required_string(response, "status")? != expected_status {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        Ok(())
    }

    fn validate_item_indexes(&self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        if required_u64(event, "output_index")? != 0
            || required_u64(event, "content_index")? != 0
            || required_string(event, "item_id")? != self.item_id()?
        {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        Ok(())
    }

    fn accept_optional_terminal_output(
        &mut self,
        response: &Map<String, Value>,
        allowed_statuses: &[&str],
    ) -> Result<(), OpenAiStreamError> {
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .ok_or(OpenAiStreamError::MalformedEvent)?;
        if output.is_empty() {
            return Ok(());
        }
        let item = output
            .first()
            .and_then(Value::as_object)
            .ok_or(OpenAiStreamError::MalformedEvent)?;
        if output.len() != 1 {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        let status = required_string(item, "status")?;
        if !allowed_statuses.contains(&status) {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        if self.item_id.is_none() {
            let item_id = required_string(item, "id")?;
            validate_identifier(item_id)?;
            let text = terminal_item_text(item, status)?;
            let next = self
                .text
                .len()
                .checked_add(text.len())
                .filter(|length| *length <= OPENAI_MAX_NORMALIZED_TEXT_BYTES)
                .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
            if !self.text.is_empty() {
                return Err(OpenAiStreamError::CorrelationMismatch);
            }
            self.text.reserve(next);
            self.text.push_str(text);
            self.item_id = Some(item_id.to_owned());
            if !text.is_empty() {
                self.push_normalized(ProviderStreamEventKind::TextDelta {
                    text: text.to_owned(),
                })?;
            }
        }
        validate_completed_item(item, self.item_id()?, &self.text, status)
    }

    fn push_optional_usage(
        &mut self,
        response: &Map<String, Value>,
    ) -> Result<(), OpenAiStreamError> {
        match response.get("usage") {
            Some(value) if !value.is_null() => {
                let usage = parse_usage(value)?;
                self.push_normalized(ProviderStreamEventKind::Usage { usage })
            }
            Some(_) | None => self.push_normalized(ProviderStreamEventKind::UsageUnavailable),
        }
    }

    fn ensure_terminal_prefix_allowed(&mut self) -> Result<(), OpenAiStreamError> {
        self.ensure_started()
    }

    fn ensure_started(&mut self) -> Result<(), OpenAiStreamError> {
        if self.normalized.is_empty() {
            self.push_normalized(ProviderStreamEventKind::Started)?;
        }
        Ok(())
    }

    fn push_normalized(&mut self, kind: ProviderStreamEventKind) -> Result<(), OpenAiStreamError> {
        let sequence = u64::try_from(self.normalized.len())
            .map_err(|_| OpenAiStreamError::StreamLimitExceeded)?;
        let event = ProviderStreamEvent::new(sequence, kind)
            .map_err(|_| OpenAiStreamError::MalformedEvent)?;
        self.normalized.push(event);
        Ok(())
    }

    fn item_id(&self) -> Result<&str, OpenAiStreamError> {
        self.item_id
            .as_deref()
            .ok_or(OpenAiStreamError::CorrelationMismatch)
    }
}

pub fn decode_transport_response(
    response: &OpenAiTransportResponse,
) -> Result<Vec<ProviderStreamEvent>, OpenAiStreamError> {
    if response.chunks().len() > OPENAI_MAX_TRANSPORT_CHUNKS {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    if response.status() == 200 && response.content_type() == "text/event-stream" {
        let mut decoder = OpenAiSseDecoder::default();
        for chunk in response.chunks() {
            decoder.push(chunk)?;
        }
        return decoder.finish();
    }
    if (200..300).contains(&response.status())
        || response.content_type() != "application/json"
        || response.chunks().is_empty()
    {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    let body = response.chunks().concat();
    if body.is_empty() || body.len() > OPENAI_MAX_SSE_FRAME_BYTES {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    validate_remote_rejection(&body)?;
    [
        ProviderStreamEventKind::Started,
        ProviderStreamEventKind::UsageUnavailable,
        ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
        },
    ]
    .into_iter()
    .enumerate()
    .map(|(sequence, kind)| {
        ProviderStreamEvent::new(sequence as u64, kind)
            .map_err(|_| OpenAiStreamError::MalformedEvent)
    })
    .collect()
}

fn validate_remote_rejection(body: &[u8]) -> Result<(), OpenAiStreamError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| OpenAiStreamError::MalformedEvent)?;
    let root = value.as_object().ok_or(OpenAiStreamError::MalformedEvent)?;
    require_keys(root, &["error"])?;
    let error = required_object(root, "error")?;
    let allowed = ["code", "message", "param", "type"];
    if !error.keys().all(|key| allowed.contains(&key.as_str())) {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    validate_diagnostic_string(error, "message")?;
    if let Some(value) = error.get("type") {
        validate_bounded_string(value)?;
    }
    if let Some(value) = error.get("code") {
        validate_bounded_string(value)?;
    }
    Ok(())
}

fn validate_response_guards(response: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
    if response.get("object").and_then(Value::as_str) != Some("response")
        || response.get("model").and_then(Value::as_str) != Some(OPENAI_REQUEST_MODEL)
        || response.get("service_tier").and_then(Value::as_str) != Some(OPENAI_SERVICE_TIER)
    {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    if response
        .get("background")
        .is_some_and(|value| value != false)
        || response
            .get("tools")
            .is_some_and(|value| value.as_array().is_none_or(|tools| !tools.is_empty()))
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn validate_terminal_response_guards(
    response: &Map<String, Value>,
    requires_error: bool,
    requires_incomplete_details: bool,
) -> Result<(), OpenAiStreamError> {
    let error_present = response.get("error").is_some_and(|value| !value.is_null());
    let incomplete_present = response
        .get("incomplete_details")
        .is_some_and(|value| !value.is_null());
    if error_present != requires_error || incomplete_present != requires_incomplete_details {
        return Err(OpenAiStreamError::IllegalTransition);
    }
    if requires_error {
        let error = required_object(response, "error")?;
        validate_diagnostic_string(error, "code")?;
        validate_diagnostic_string(error, "message")?;
    }
    if requires_incomplete_details {
        let details = required_object(response, "incomplete_details")?;
        require_keys(details, &["reason"])?;
        validate_diagnostic_string(details, "reason")?;
    }
    Ok(())
}

fn validate_added_item(item: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
    require_keys(item, &["content", "id", "role", "status", "type"])?;
    if required_string(item, "type")? != "message"
        || required_string(item, "status")? != "in_progress"
        || required_string(item, "role")? != "assistant"
        || !item
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn terminal_item_text<'a>(
    item: &'a Map<String, Value>,
    status: &str,
) -> Result<&'a str, OpenAiStreamError> {
    require_keys(item, &["content", "id", "role", "status", "type"])?;
    if required_string(item, "type")? != "message"
        || required_string(item, "status")? != status
        || required_string(item, "role")? != "assistant"
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    let content = item
        .get("content")
        .and_then(Value::as_array)
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    if content.len() != 1 {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    let part = content[0]
        .as_object()
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    require_keys(part, &["annotations", "text", "type"])?;
    if required_string(part, "type")? != "output_text"
        || !part
            .get("annotations")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    required_string(part, "text")
}

fn validate_completed_item(
    item: &Map<String, Value>,
    item_id: &str,
    text: &str,
    status: &str,
) -> Result<(), OpenAiStreamError> {
    require_keys(item, &["content", "id", "role", "status", "type"])?;
    if required_string(item, "id")? != item_id
        || required_string(item, "type")? != "message"
        || required_string(item, "status")? != status
        || required_string(item, "role")? != "assistant"
    {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    let content = item
        .get("content")
        .and_then(Value::as_array)
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    if content.len() != 1 {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    validate_part(
        content[0]
            .as_object()
            .ok_or(OpenAiStreamError::MalformedEvent)?,
        text,
        false,
    )
}

fn validate_part(
    part: &Map<String, Value>,
    text: &str,
    added: bool,
) -> Result<(), OpenAiStreamError> {
    require_keys(part, &["annotations", "text", "type"])?;
    if required_string(part, "type")? != "output_text"
        || required_string(part, "text")? != text
        || !part
            .get("annotations")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        || (added && !text.is_empty())
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn validate_output(
    response: &Map<String, Value>,
    item_id: &str,
    text: &str,
    status: &str,
    allow_empty: bool,
) -> Result<(), OpenAiStreamError> {
    let output = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    if output.is_empty() && allow_empty {
        return Ok(());
    }
    if output.len() != 1 {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    validate_completed_item(
        output[0]
            .as_object()
            .ok_or(OpenAiStreamError::MalformedEvent)?,
        item_id,
        text,
        status,
    )
}

fn parse_usage(value: &Value) -> Result<ProviderUsage, OpenAiStreamError> {
    let usage = value.as_object().ok_or(OpenAiStreamError::InvalidUsage)?;
    require_keys(
        usage,
        &[
            "input_tokens",
            "input_tokens_details",
            "output_tokens",
            "output_tokens_details",
            "total_tokens",
        ],
    )
    .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let input = required_u64(usage, "input_tokens").map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let output =
        required_u64(usage, "output_tokens").map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let total = required_u64(usage, "total_tokens").map_err(|_| OpenAiStreamError::InvalidUsage)?;
    if input.checked_add(output) != Some(total) {
        return Err(OpenAiStreamError::InvalidUsage);
    }
    let input_details = required_object(usage, "input_tokens_details")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    require_keys(input_details, &["cached_tokens"]).map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let cached = required_u64(input_details, "cached_tokens")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let output_details = required_object(usage, "output_tokens_details")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    require_keys(output_details, &["reasoning_tokens"])
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let reasoning = required_u64(output_details, "reasoning_tokens")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    ProviderUsage::new(input, output, cached, reasoning)
        .map_err(|_| OpenAiStreamError::InvalidUsage)
}

fn validate_identifier(value: &str) -> Result<(), OpenAiStreamError> {
    if value.is_empty()
        || value.len() > MAX_REMOTE_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    Ok(())
}

fn validate_diagnostic_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), OpenAiStreamError> {
    let value = object.get(key).ok_or(OpenAiStreamError::MalformedEvent)?;
    validate_bounded_string(value)
}

fn validate_bounded_string(value: &Value) -> Result<(), OpenAiStreamError> {
    let value = value.as_str().ok_or(OpenAiStreamError::MalformedEvent)?;
    if value.is_empty() || value.len() > MAX_REMOTE_DIAGNOSTIC_BYTES {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    Ok(())
}

fn validate_empty_logprobs(event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
    if event
        .get("logprobs")
        .is_some_and(|value| value.as_array().is_none_or(|values| !values.is_empty()))
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn require_empty_output(response: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
    if !response
        .get("output")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn require_null_or_missing(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), OpenAiStreamError> {
    if object.get(key).is_some_and(|value| !value.is_null()) {
        return Err(OpenAiStreamError::IllegalTransition);
    }
    Ok(())
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or(OpenAiStreamError::MalformedEvent)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(OpenAiStreamError::MalformedEvent)
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(OpenAiStreamError::MalformedEvent)
}

fn require_keys(object: &Map<String, Value>, exact: &[&str]) -> Result<(), OpenAiStreamError> {
    let expected = exact.iter().copied().collect::<BTreeSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    Ok(())
}

fn require_keys_subset(
    object: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), OpenAiStreamError> {
    if !object.keys().all(|key| allowed.contains(&key.as_str()))
        || !required.iter().all(|key| object.contains_key(*key))
    {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    Ok(())
}
