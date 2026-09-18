use std::str;

use thiserror::Error;

const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINES: usize = 32_768;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SseFrame {
    pub(crate) event: Option<String>,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Error)]
pub(crate) enum SseError {
    #[error("native wire SSE framing is malformed")]
    Malformed,
    #[error("native wire SSE bound exceeded")]
    BoundExceeded,
    #[error("native wire SSE stream is truncated")]
    Truncated,
}

#[derive(Debug)]
pub(crate) struct SseFramer {
    pending: Vec<u8>,
    event: Option<String>,
    data: Vec<u8>,
    frame_bytes: usize,
    stream_bytes: usize,
    lines: usize,
    max_frame_bytes: usize,
}

impl SseFramer {
    pub(crate) const fn new(max_frame_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            event: None,
            data: Vec::new(),
            frame_bytes: 0,
            stream_bytes: 0,
            lines: 0,
            max_frame_bytes,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseFrame>, SseError> {
        self.stream_bytes = self
            .stream_bytes
            .checked_add(bytes.len())
            .filter(|value| *value <= MAX_STREAM_BYTES)
            .ok_or(SseError::BoundExceeded)?;
        self.pending.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending.drain(..=index).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.lines = self
                .lines
                .checked_add(1)
                .filter(|value| *value <= MAX_LINES)
                .ok_or(SseError::BoundExceeded)?;
            self.frame_bytes = self
                .frame_bytes
                .checked_add(line.len() + 1)
                .filter(|value| *value <= self.max_frame_bytes)
                .ok_or(SseError::BoundExceeded)?;
            if line.is_empty() {
                if self.event.is_some() || !self.data.is_empty() {
                    frames.push(self.take_frame());
                }
                self.frame_bytes = 0;
                continue;
            }
            let line = str::from_utf8(&line).map_err(|_| SseError::Malformed)?;
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = line.split_once(':').ok_or(SseError::Malformed)?;
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" if self.event.is_none() => self.event = Some(value.to_owned()),
                "data" => {
                    let next = self
                        .data
                        .len()
                        .checked_add(usize::from(!self.data.is_empty()))
                        .and_then(|size| size.checked_add(value.len()))
                        .filter(|size| *size <= self.max_frame_bytes)
                        .ok_or(SseError::BoundExceeded)?;
                    self.data.reserve(next - self.data.len());
                    if !self.data.is_empty() {
                        self.data.push(b'\n');
                    }
                    self.data.extend_from_slice(value.as_bytes());
                }
                _ => return Err(SseError::Malformed),
            }
        }
        if self.pending.len() > self.max_frame_bytes {
            return Err(SseError::BoundExceeded);
        }
        Ok(frames)
    }

    pub(crate) fn finish(self) -> Result<(), SseError> {
        if self.pending.is_empty() && self.event.is_none() && self.data.is_empty() {
            Ok(())
        } else {
            Err(SseError::Truncated)
        }
    }

    fn take_frame(&mut self) -> SseFrame {
        SseFrame {
            event: self.event.take(),
            data: std::mem::take(&mut self.data),
        }
    }
}
