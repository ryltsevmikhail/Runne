use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::Value;
use thiserror::Error;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_FRAME: usize = 256 * 1024;
const MAX_EVENTS: usize = 16_384;

/// Sanitized Responses stream failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResponsesStreamError {
    /// Invalid SSE or JSON.
    #[error("malformed responses event")]
    Malformed,
    /// Identity or sequence changed.
    #[error("responses identity mismatch")]
    Identity,
    /// Invalid lifecycle.
    #[error("invalid responses lifecycle")]
    Lifecycle,
    /// Bound exceeded.
    #[error("responses stream limit exceeded")]
    Limit,
    /// Stream ended without a terminal response.
    #[error("responses terminal event missing")]
    TerminalMissing,
    /// Usage appeared more than once or was invalid.
    #[error("invalid responses usage")]
    Usage,
}

#[derive(Default)]
struct State {
    id: Option<String>,
    model: Option<String>,
    started: bool,
    terminal: bool,
    usage: bool,
    next_seq: u64,
    events: Vec<ProviderStreamEvent>,
}

/// Incremental, byte-fragmentation-safe Responses SSE decoder.
#[derive(Default)]
pub struct ResponsesStreamDecoder {
    pending: Vec<u8>,
    event: Option<String>,
    data: Vec<String>,
    bytes: usize,
    frames: usize,
    state: State,
    profile: Option<ResponsesProfileRef>,
}

#[derive(Clone)]
struct ResponsesProfileRef {
    model: String,
    aliases: Vec<String>,
}
impl ResponsesStreamDecoder {
    /// Creates a decoder enforcing the profile's model and explicit aliases.
    pub fn for_profile(profile: &crate::ResponsesProfile) -> Self {
        Self {
            profile: Some(ResponsesProfileRef {
                model: profile.model().to_owned(),
                aliases: profile.aliases().to_vec(),
            }),
            ..Self::default()
        }
    }
    /// Creates a decoder without model pinning (identity is still pinned after creation).
    pub fn generic() -> Self {
        Self::default()
    }
    /// Adds an arbitrary body fragment.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ResponsesStreamError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|v| *v <= MAX_BYTES)
            .ok_or(ResponsesStreamError::Limit)?;
        self.pending.extend_from_slice(bytes);
        if self.pending.len() > MAX_FRAME {
            return Err(ResponsesStreamError::Limit);
        }
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let line = self.pending.drain(..=pos).collect::<Vec<_>>();
            self.line(&line[..line.len() - 1])?;
        }
        Ok(())
    }
    /// Closes the stream and returns normalized Runne events.
    pub fn finish(self) -> Result<Vec<ProviderStreamEvent>, ResponsesStreamError> {
        if !self.pending.is_empty()
            || self.event.is_some()
            || !self.data.is_empty()
            || !self.state.terminal
        {
            return Err(ResponsesStreamError::TerminalMissing);
        }
        Ok(self.state.events)
    }
    fn line(&mut self, raw: &[u8]) -> Result<(), ResponsesStreamError> {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.is_empty() {
            return self.frame();
        }
        let line = std::str::from_utf8(raw).map_err(|_| ResponsesStreamError::Malformed)?;
        if line.starts_with(':') {
            return Ok(());
        }
        let (key, value) = line
            .split_once(':')
            .ok_or(ResponsesStreamError::Malformed)?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match key {
            "event" if self.event.is_none() && !value.is_empty() => {
                self.event = Some(value.to_owned());
            }
            "data" => self.data.push(value.to_owned()),
            _ => return Err(ResponsesStreamError::Malformed),
        }
        Ok(())
    }
    fn frame(&mut self) -> Result<(), ResponsesStreamError> {
        if self.event.is_none() && self.data.is_empty() {
            return Ok(());
        }
        let name = self.event.take().ok_or(ResponsesStreamError::Malformed)?;
        let value: Value = serde_json::from_str(&self.data.join("\n"))
            .map_err(|_| ResponsesStreamError::Malformed)?;
        self.data.clear();
        self.frames = self
            .frames
            .checked_add(1)
            .filter(|v| *v <= MAX_EVENTS)
            .ok_or(ResponsesStreamError::Limit)?;
        self.accept(&name, &value)
    }
    fn accept(&mut self, name: &str, v: &Value) -> Result<(), ResponsesStreamError> {
        if self.state.terminal {
            return Err(ResponsesStreamError::Lifecycle);
        }
        if v.get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind != name)
        {
            return Err(ResponsesStreamError::Malformed);
        }
        if let Some(seq) = v.get("sequence_number").and_then(Value::as_u64) {
            if seq != self.state.next_seq {
                return Err(ResponsesStreamError::Identity);
            }
            self.state.next_seq += 1;
        }
        let response = v.get("response").unwrap_or(v);
        if let Some(id) = response.get("id").and_then(Value::as_str) {
            if let Some(old) = &self.state.id {
                if old != id {
                    return Err(ResponsesStreamError::Identity);
                }
            } else {
                self.state.id = Some(id.to_owned());
            }
        }
        if let Some(model) = response.get("model").and_then(Value::as_str) {
            if let Some(profile) = &self.profile {
                if model != profile.model && !profile.aliases.iter().any(|a| a == model) {
                    return Err(ResponsesStreamError::Identity);
                }
            }
            if let Some(old) = &self.state.model {
                if old != model {
                    return Err(ResponsesStreamError::Identity);
                }
            } else {
                self.state.model = Some(model.to_owned());
            }
        }
        match name {
            "response.created" => {
                if self.state.started {
                    return Err(ResponsesStreamError::Lifecycle);
                }
                if self.state.id.is_none() || self.state.model.is_none() {
                    return Err(ResponsesStreamError::Identity);
                }
                self.state.started = true;
                self.emit(ProviderStreamEventKind::Started)?;
            }
            "response.output_text.delta" => {
                if !self.state.started {
                    return Err(ResponsesStreamError::Lifecycle);
                }
                let text = v
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or(ResponsesStreamError::Malformed)?;
                if text.len() > 65_536 {
                    return Err(ResponsesStreamError::Limit);
                }
                self.emit(ProviderStreamEventKind::TextDelta {
                    text: text.to_owned(),
                })?;
            }
            "response.completed" | "response.incomplete" | "response.failed" => {
                if !self.state.started {
                    return Err(ResponsesStreamError::Lifecycle);
                }
                self.add_usage(response)?;
                let reason = if name == "response.completed" {
                    ProviderFinishReason::Stop
                } else if name == "response.incomplete" {
                    ProviderFinishReason::Length
                } else {
                    ProviderFinishReason::Error
                };
                let disposition = if name == "response.completed" {
                    ProviderTerminalDisposition::Completed
                } else if name == "response.incomplete" {
                    ProviderTerminalDisposition::RemoteIncomplete
                } else {
                    ProviderTerminalDisposition::RemoteFailed
                };
                self.emit(ProviderStreamEventKind::Finished {
                    disposition,
                    reason,
                })?;
                self.state.terminal = true;
            }
            "response.output_text.done" | "response.in_progress" => {
                if !self.state.started {
                    return Err(ResponsesStreamError::Lifecycle);
                }
            }
            _ => return Err(ResponsesStreamError::Malformed),
        }
        Ok(())
    }
    fn add_usage(&mut self, response: &Value) -> Result<(), ResponsesStreamError> {
        if self.state.usage {
            return Err(ResponsesStreamError::Usage);
        }
        let Some(u) = response.get("usage") else {
            self.emit(ProviderStreamEventKind::UsageUnavailable)?;
            return Ok(());
        };
        let input = u
            .get("input_tokens")
            .and_then(Value::as_u64)
            .ok_or(ResponsesStreamError::Usage)?;
        let output = u
            .get("output_tokens")
            .and_then(Value::as_u64)
            .ok_or(ResponsesStreamError::Usage)?;
        let cached = detail_counter(u, "input_tokens_details", "cached_tokens")?;
        let reasoning = detail_counter(u, "output_tokens_details", "reasoning_tokens")?;
        let usage = ProviderUsage::new(input, output, cached, reasoning)
            .map_err(|_| ResponsesStreamError::Usage)?;
        self.state.usage = true;
        self.emit(ProviderStreamEventKind::Usage { usage })
    }
    fn emit(&mut self, kind: ProviderStreamEventKind) -> Result<(), ResponsesStreamError> {
        let event = ProviderStreamEvent::new(self.state.events.len() as u64, kind)
            .map_err(|_| ResponsesStreamError::Malformed)?;
        self.state.events.push(event);
        Ok(())
    }
}

fn detail_counter(
    usage: &Value,
    details_name: &str,
    counter_name: &str,
) -> Result<u64, ResponsesStreamError> {
    let Some(details) = usage.get(details_name) else {
        return Ok(0);
    };
    let Some(counter) = details.get(counter_name) else {
        return Ok(0);
    };
    counter.as_u64().ok_or(ResponsesStreamError::Usage)
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
