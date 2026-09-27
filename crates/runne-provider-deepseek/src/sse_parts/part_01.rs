use std::collections::BTreeSet;

use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::{Map, Value};

use crate::{
    DEEPSEEK_MAX_DECODED_STREAM_BYTES, DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES, DEEPSEEK_MAX_SSE_EVENTS,
    DEEPSEEK_MAX_SSE_FRAME_BYTES, DEEPSEEK_MAX_SSE_LINES, DEEPSEEK_REQUEST_MODEL,
};

const MAX_REMOTE_IDENTIFIER_BYTES: usize = 256;
const MAX_REMOTE_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Debug)]
struct Lifecycle {
    stage: LifecycleStage,
    response_id: Option<String>,
    item_id: Option<String>,
    text: String,
    normalized: Vec<ProviderStreamEvent>,
    last_remote_sequence: Option<u64>,
    trace: DecodeTrace,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            stage: LifecycleStage::Start,
            response_id: None,
            item_id: None,
            text: String::new(),
            normalized: Vec::new(),
            last_remote_sequence: None,
            trace: DecodeTrace::default(),
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
        self.pending.try_reserve(bytes.len()).map_err(|_| {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseLine,
                DeepSeekDecodeSchemaNode::SseLine,
                DeepSeekDecodeField::Unknown,
                DeepSeekDecodeIssue::BoundExceeded,
            );
            DeepSeekStreamError::StreamLimitExceeded
        })?;
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
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseLine,
                DeepSeekDecodeSchemaNode::SseLine,
                DeepSeekDecodeField::Unknown,
                DeepSeekDecodeIssue::BoundExceeded,
            );
            return Err(DeepSeekStreamError::StreamLimitExceeded);
        }
        Ok(())
    }

    /// Closes the decoder and returns provider-neutral ordered evidence.
    ///
    /// # Errors
    ///
    /// Requires a blank-frame-delimited terminal event and no trailing bytes.
    pub fn finish(mut self) -> Result<Vec<ProviderStreamEvent>, DeepSeekStreamError> {
        self.finish_inner()
    }

    pub(crate) fn finish_with_diagnostic(
        mut self,
    ) -> (
        Result<Vec<ProviderStreamEvent>, DeepSeekStreamError>,
        Option<DeepSeekDecodeDiagnostic>,
    ) {
        let result = self.finish_inner();
        (result, self.lifecycle.trace.failure())
    }

    pub(crate) const fn failure_diagnostic(&self) -> Option<DeepSeekDecodeDiagnostic> {
        self.lifecycle.trace.failure()
    }

    fn finish_inner(&mut self) -> Result<Vec<ProviderStreamEvent>, DeepSeekStreamError> {
        if !self.pending.is_empty()
            || self.event_name.is_some()
            || !self.data_lines.is_empty()
            || self.lifecycle.stage != LifecycleStage::Terminal
        {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::Terminal,
                DeepSeekDecodeSchemaNode::SseFrame,
                DeepSeekDecodeField::Data,
                DeepSeekDecodeIssue::TerminalEvidenceMissing,
            );
            return Err(DeepSeekStreamError::TerminalMissing);
        }
        Ok(std::mem::take(&mut self.lifecycle.normalized))
    }

    fn accept_line(&mut self, line: &[u8], wire_bytes: usize) -> Result<(), DeepSeekStreamError> {
        self.line_count = match self.line_count.checked_add(1) {
            Some(count) if count <= DEEPSEEK_MAX_SSE_LINES => count,
            _ => {
                self.lifecycle.trace.record(
                    DeepSeekDecodePhase::SseLine,
                    DeepSeekDecodeSchemaNode::SseLine,
                    DeepSeekDecodeField::Unknown,
                    DeepSeekDecodeIssue::BoundExceeded,
                );
                return Err(DeepSeekStreamError::StreamLimitExceeded);
            }
        };
        self.frame_bytes = match self.frame_bytes.checked_add(wire_bytes) {
            Some(total) if total <= DEEPSEEK_MAX_SSE_FRAME_BYTES => total,
            _ => {
                self.lifecycle.trace.record(
                    DeepSeekDecodePhase::SseLine,
                    DeepSeekDecodeSchemaNode::SseLine,
                    DeepSeekDecodeField::Unknown,
                    DeepSeekDecodeIssue::BoundExceeded,
                );
                return Err(DeepSeekStreamError::StreamLimitExceeded);
            }
        };
        if line.is_empty() {
            self.dispatch_frame()?;
            self.frame_bytes = 0;
            return Ok(());
        }
        let line = std::str::from_utf8(line).map_err(|_| {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseLine,
                DeepSeekDecodeSchemaNode::SseLine,
                DeepSeekDecodeField::Unknown,
                DeepSeekDecodeIssue::InvalidUtf8,
            );
            DeepSeekStreamError::MalformedEvent
        })?;
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = line.split_once(':').ok_or_else(|| {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseLine,
                DeepSeekDecodeSchemaNode::SseLine,
                DeepSeekDecodeField::Unknown,
                DeepSeekDecodeIssue::MissingColon,
            );
            DeepSeekStreamError::MalformedEvent
        })?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if self.event_name.is_none() && !value.is_empty() => {
                self.event_name = Some(value.to_owned());
                self.lifecycle
                    .trace
                    .set_event(DeepSeekDecodeEventKind::from_wire(value));
            }
            "data" => self.data_lines.push(value.to_owned()),
            "event" if self.event_name.is_some() => {
                self.lifecycle.trace.record(
                    DeepSeekDecodePhase::SseLine,
                    DeepSeekDecodeSchemaNode::SseLine,
                    DeepSeekDecodeField::Event,
                    DeepSeekDecodeIssue::DuplicateEventField,
                );
                return Err(DeepSeekStreamError::MalformedEvent);
            }
            "event" => {
                self.lifecycle.trace.record(
                    DeepSeekDecodePhase::SseLine,
                    DeepSeekDecodeSchemaNode::SseLine,
                    DeepSeekDecodeField::Event,
                    DeepSeekDecodeIssue::EmptyEventName,
                );
                return Err(DeepSeekStreamError::MalformedEvent);
            }
            _ => {
                self.lifecycle.trace.record(
                    DeepSeekDecodePhase::SseLine,
                    DeepSeekDecodeSchemaNode::SseLine,
                    DeepSeekDecodeField::from_wire(field),
                    DeepSeekDecodeIssue::UnsupportedSseField,
                );
                return Err(DeepSeekStreamError::MalformedEvent);
            }
        }
        Ok(())
    }

    fn dispatch_frame(&mut self) -> Result<(), DeepSeekStreamError> {
        if self.event_name.is_none() && self.data_lines.is_empty() {
            self.lifecycle.trace.clear_event();
            return Ok(());
        }
        let event_name = self.event_name.take().ok_or_else(|| {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseFrame,
                DeepSeekDecodeSchemaNode::SseFrame,
                DeepSeekDecodeField::Event,
                DeepSeekDecodeIssue::MissingEventName,
            );
            DeepSeekStreamError::MalformedEvent
        })?;
        if self.data_lines.is_empty() {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseFrame,
                DeepSeekDecodeSchemaNode::SseFrame,
                DeepSeekDecodeField::Data,
                DeepSeekDecodeIssue::MissingData,
            );
            return Err(DeepSeekStreamError::MalformedEvent);
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        self.event_count = self
            .event_count
            .checked_add(1)
            .filter(|count| *count <= DEEPSEEK_MAX_SSE_EVENTS)
            .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
        let value: Value = serde_json::from_str(&data).map_err(|_| {
            self.lifecycle.trace.record(
                DeepSeekDecodePhase::SseFrame,
                DeepSeekDecodeSchemaNode::SseFrame,
                DeepSeekDecodeField::Data,
                DeepSeekDecodeIssue::InvalidJson,
            );
            DeepSeekStreamError::MalformedEvent
        })?;
        let result = self.lifecycle.accept(&event_name, &value);
        if result.is_ok() {
            self.lifecycle.trace.clear_event();
        }
        result
    }
}
