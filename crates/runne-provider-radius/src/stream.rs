use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::{Map, Value};
use thiserror::Error;

const MAX_FRAME: usize = 65_536;
const MAX_STREAM: usize = 8 * 1024 * 1024;
const MAX_EVENTS: usize = 16_384;

/// Radius `pi-messages` decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RadiusStreamError {
    /// SSE or JSON shape is malformed.
    #[error("Radius stream event is malformed")]
    Malformed,
    /// A frame, stream, text, or event bound was exceeded.
    #[error("Radius stream bound exceeded")]
    BoundExceeded,
    /// Usage is absent or mathematically inconsistent.
    #[error("Radius stream usage is invalid")]
    InvalidUsage,
    /// The stream ended without a valid terminal event.
    #[error("Radius stream terminal is missing")]
    TerminalMissing,
    /// A thinking/tool event is outside this text-only codec.
    #[error("Radius stream content is not text-only")]
    UnsupportedContent,
}

/// Incremental strict decoder for the pinned Radius SSE event lifecycle.
#[derive(Debug)]
pub struct RadiusStreamDecoder {
    pending: Vec<u8>,
    aggregate: Vec<u8>,
    events: Vec<ProviderStreamEvent>,
    stream_bytes: usize,
    started: bool,
    text_started: bool,
    text_ended: bool,
    terminal: bool,
    usage: Option<ProviderUsage>,
}

impl Default for RadiusStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RadiusStreamDecoder {
    /// Creates an identity-unbound decoder for a pure wire response.
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
            aggregate: Vec::new(),
            events: Vec::new(),
            stream_bytes: 0,
            started: false,
            text_started: false,
            text_ended: false,
            terminal: false,
            usage: None,
        }
    }
    /// Accepts an arbitrary response-body fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), RadiusStreamError> {
        self.stream_bytes = self
            .stream_bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_STREAM)
            .ok_or(RadiusStreamError::BoundExceeded)?;
        self.pending.extend_from_slice(bytes);
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending.drain(..=index).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            let line = std::str::from_utf8(&line).map_err(|_| RadiusStreamError::Malformed)?;
            let data = line
                .strip_prefix("data:")
                .ok_or(RadiusStreamError::Malformed)?
                .trim_start();
            if data == "[DONE]" || data.is_empty() {
                return Err(RadiusStreamError::Malformed);
            }
            let value: Value =
                serde_json::from_str(data).map_err(|_| RadiusStreamError::Malformed)?;
            let frame_limit = if value.get("type").and_then(Value::as_str) == Some("text_end") {
                MAX_STREAM
            } else {
                MAX_FRAME
            };
            if data.len() > frame_limit {
                return Err(RadiusStreamError::BoundExceeded);
            }
            self.accept(&value)?;
        }
        if self.pending.len() > MAX_STREAM
            || (self.pending.len() > MAX_FRAME && !partial_text_end(&self.pending))
        {
            return Err(RadiusStreamError::BoundExceeded);
        }
        Ok(())
    }
    /// Finishes framing and returns normalized ordered events.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, RadiusStreamError> {
        if !self.pending.is_empty() {
            return Err(RadiusStreamError::TerminalMissing);
        }
        if !self.terminal || !self.text_ended || self.usage.is_none() {
            return Err(RadiusStreamError::TerminalMissing);
        }
        Ok(self.events)
    }
    fn accept(&mut self, value: &Value) -> Result<(), RadiusStreamError> {
        let object = value.as_object().ok_or(RadiusStreamError::Malformed)?;
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .ok_or(RadiusStreamError::Malformed)?;
        match kind {
            "start" => {
                if self.started || self.terminal {
                    return Err(RadiusStreamError::Malformed);
                }
                self.started = true;
                self.push_event(ProviderStreamEventKind::Started)
            }
            "text_start" => self.text_start(object),
            "text_delta" => self.text_delta(object),
            "text_end" => self.text_end(object),
            "done" | "error" => self.done(object, kind),
            "thinking_start" | "thinking_delta" | "thinking_end" | "toolcall_start"
            | "toolcall_delta" | "toolcall_end" => Err(RadiusStreamError::UnsupportedContent),
            _ => Err(RadiusStreamError::Malformed),
        }
    }
    fn text_start(&mut self, object: &Map<String, Value>) -> Result<(), RadiusStreamError> {
        Self::require_index(object)?;
        if !self.started || self.text_started || self.terminal {
            return Err(RadiusStreamError::Malformed);
        }
        self.text_started = true;
        Ok(())
    }
    fn text_delta(&mut self, object: &Map<String, Value>) -> Result<(), RadiusStreamError> {
        Self::require_index(object)?;
        if !self.text_started || self.text_ended || self.terminal {
            return Err(RadiusStreamError::Malformed);
        }
        let delta = object
            .get("delta")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(RadiusStreamError::Malformed)?;
        let next = self
            .aggregate
            .len()
            .checked_add(delta.len())
            .filter(|size| *size <= MAX_STREAM)
            .ok_or(RadiusStreamError::BoundExceeded)?;
        self.aggregate.reserve(next - self.aggregate.len());
        self.aggregate.extend_from_slice(delta.as_bytes());
        self.push_event(ProviderStreamEventKind::TextDelta {
            text: delta.to_owned(),
        })
    }
    fn text_end(&mut self, object: &Map<String, Value>) -> Result<(), RadiusStreamError> {
        Self::require_index(object)?;
        if !self.text_started || self.text_ended || self.terminal {
            return Err(RadiusStreamError::Malformed);
        }
        if object.get("content").and_then(Value::as_str)
            != Some(std::str::from_utf8(&self.aggregate).map_err(|_| RadiusStreamError::Malformed)?)
        {
            return Err(RadiusStreamError::Malformed);
        }
        self.text_ended = true;
        Ok(())
    }
    fn done(&mut self, object: &Map<String, Value>, kind: &str) -> Result<(), RadiusStreamError> {
        if !self.started || !self.text_ended || self.terminal {
            return Err(RadiusStreamError::Malformed);
        }
        let usage = parse_usage(object.get("usage").ok_or(RadiusStreamError::InvalidUsage)?)?;
        self.usage = Some(usage);
        self.push_event(ProviderStreamEventKind::Usage { usage })?;
        let reason = if kind == "error" {
            match object.get("reason").and_then(Value::as_str) {
                Some("error" | "aborted") => ProviderFinishReason::Error,
                _ => return Err(RadiusStreamError::Malformed),
            }
        } else {
            match object
                .get("reason")
                .and_then(Value::as_str)
                .ok_or(RadiusStreamError::Malformed)?
            {
                "stop" => ProviderFinishReason::Stop,
                "length" => ProviderFinishReason::Length,
                "toolUse" => return Err(RadiusStreamError::UnsupportedContent),
                _ => return Err(RadiusStreamError::Malformed),
            }
        };
        let disposition = if kind == "error" {
            ProviderTerminalDisposition::RemoteFailed
        } else if reason == ProviderFinishReason::Stop {
            ProviderTerminalDisposition::Completed
        } else {
            ProviderTerminalDisposition::RemoteIncomplete
        };
        self.push_event(ProviderStreamEventKind::Finished {
            disposition,
            reason,
        })?;
        self.terminal = true;
        Ok(())
    }
    fn require_index(object: &Map<String, Value>) -> Result<(), RadiusStreamError> {
        if object.get("contentIndex").and_then(Value::as_u64) == Some(0) {
            Ok(())
        } else {
            Err(RadiusStreamError::Malformed)
        }
    }
    fn push_event(&mut self, kind: ProviderStreamEventKind) -> Result<(), RadiusStreamError> {
        if self.events.len() >= MAX_EVENTS {
            return Err(RadiusStreamError::BoundExceeded);
        }
        let sequence =
            u64::try_from(self.events.len()).map_err(|_| RadiusStreamError::BoundExceeded)?;
        self.events.push(
            ProviderStreamEvent::new(sequence, kind).map_err(|_| RadiusStreamError::Malformed)?,
        );
        Ok(())
    }
}

fn partial_text_end(pending: &[u8]) -> bool {
    pending.starts_with(b"data: {\"type\":\"text_end\"")
}

fn parse_usage(value: &Value) -> Result<ProviderUsage, RadiusStreamError> {
    let object = value.as_object().ok_or(RadiusStreamError::InvalidUsage)?;
    let input = token(object, "input")?;
    let output = token(object, "output")?;
    let cached = token(object, "cacheRead")?;
    let total = token(object, "totalTokens")?;
    if total
        != input
            .checked_add(output)
            .ok_or(RadiusStreamError::InvalidUsage)?
    {
        return Err(RadiusStreamError::InvalidUsage);
    }
    ProviderUsage::new(input, output, cached, 0).map_err(|_| RadiusStreamError::InvalidUsage)
}

fn token(object: &Map<String, Value>, key: &str) -> Result<u64, RadiusStreamError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= 1_000_000_000)
        .ok_or(RadiusStreamError::InvalidUsage)
}
