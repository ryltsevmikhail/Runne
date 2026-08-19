//! Strict bounded Server-Sent Events framing for replay delivery.

use std::time::Duration;

/// Maximum encoded bytes accepted for one complete SSE frame.
pub const MAXIMUM_SSE_FRAME_BYTES: usize = 256 * 1024;

/// Maximum time accepted without receiving a delivery or heartbeat.
pub const SSE_SILENCE_TIMEOUT: Duration = Duration::from_secs(45);

const MAXIMUM_DECODER_BUFFER_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_DECODED_FRAMES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SseDecodeError {
    FrameTooLarge,
    InvalidUtf8,
    Nul,
    InvalidLineEnding,
    UnknownField,
    UnknownEvent,
    MissingEvent,
    MissingData,
    MultipleData,
    DataAfterTerminal,
    IncompleteFrame,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawSseFrame {
    Delivery(Vec<u8>),
    Terminal(Vec<u8>),
    Heartbeat,
}

#[derive(Default)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    terminal_seen: bool,
}

impl SseDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<RawSseFrame>, SseDecodeError> {
        if self.terminal_seen && !bytes.is_empty() {
            return Err(SseDecodeError::DataAfterTerminal);
        }
        if bytes.contains(&0) {
            return Err(SseDecodeError::Nul);
        }
        if self.buffer.len().saturating_add(bytes.len()) > MAXIMUM_DECODER_BUFFER_BYTES {
            return Err(SseDecodeError::FrameTooLarge);
        }
        self.buffer.extend_from_slice(bytes);

        let mut frames = Vec::new();
        while let Some((body_end, consumed_end)) = find_complete_frame(&self.buffer)? {
            if consumed_end > MAXIMUM_SSE_FRAME_BYTES {
                return Err(SseDecodeError::FrameTooLarge);
            }
            let frame = parse_frame(&self.buffer[..body_end])?;
            self.buffer.drain(..consumed_end);
            if matches!(frame, RawSseFrame::Terminal(_)) {
                self.terminal_seen = true;
            }
            frames.push(frame);
            if frames.len() > MAXIMUM_DECODED_FRAMES {
                return Err(SseDecodeError::FrameTooLarge);
            }
            if self.terminal_seen && !self.buffer.is_empty() {
                return Err(SseDecodeError::DataAfterTerminal);
            }
        }

        if self.buffer.len() > MAXIMUM_SSE_FRAME_BYTES {
            return Err(SseDecodeError::FrameTooLarge);
        }
        Ok(frames)
    }

    pub const fn finish(&self) -> Result<(), SseDecodeError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(SseDecodeError::IncompleteFrame)
        }
    }
}

fn find_complete_frame(bytes: &[u8]) -> Result<Option<(usize, usize)>, SseDecodeError> {
    let mut line_start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'\r' {
            if bytes.get(index + 1).is_some_and(|next| *next != b'\n') {
                return Err(SseDecodeError::InvalidLineEnding);
            }
            continue;
        }
        if byte != b'\n' {
            continue;
        }
        let body_end = if index > line_start && bytes[index - 1] == b'\r' {
            index - 1
        } else {
            index
        };
        if body_end == line_start {
            return Ok(Some((line_start, index + 1)));
        }
        line_start = index + 1;
    }
    Ok(None)
}

fn parse_frame(bytes: &[u8]) -> Result<RawSseFrame, SseDecodeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SseDecodeError::InvalidUtf8)?;
    let mut event = None;
    let mut data = None;
    let mut comments = 0_usize;

    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.contains('\r') {
            return Err(SseDecodeError::InvalidLineEnding);
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with(':') {
            if event.is_some() || data.is_some() {
                return Err(SseDecodeError::UnknownField);
            }
            comments = comments.saturating_add(1);
            continue;
        }
        if let Some(value) = line.strip_prefix("event: ") {
            if event.replace(value).is_some() || comments > 0 {
                return Err(SseDecodeError::UnknownField);
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("data: ") {
            if data.replace(value.as_bytes().to_vec()).is_some() {
                return Err(SseDecodeError::MultipleData);
            }
            continue;
        }
        return Err(SseDecodeError::UnknownField);
    }

    if comments > 0 {
        if event.is_none() && data.is_none() {
            return Ok(RawSseFrame::Heartbeat);
        }
        return Err(SseDecodeError::UnknownField);
    }
    let event = event.ok_or(SseDecodeError::MissingEvent)?;
    let data = data.ok_or(SseDecodeError::MissingData)?;
    if data.is_empty() {
        return Err(SseDecodeError::MissingData);
    }
    match event {
        "delivery" => Ok(RawSseFrame::Delivery(data)),
        "terminal" => Ok(RawSseFrame::Terminal(data)),
        _ => Err(SseDecodeError::UnknownEvent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_fragmented_delivery_and_comment_heartbeat() {
        let mut decoder = SseDecoder::default();
        assert!(
            decoder
                .push(b"event: delivery\r\n")
                .expect("partial frame")
                .is_empty()
        );
        assert_eq!(
            decoder
                .push(b"data: {\"transportVersion\":1}\r\n\r\n: ping\n\n")
                .expect("complete frames"),
            vec![
                RawSseFrame::Delivery(br#"{"transportVersion":1}"#.to_vec()),
                RawSseFrame::Heartbeat,
            ]
        );
    }

    #[test]
    fn rejects_unknown_fields_multiple_data_and_data_after_terminal() {
        for bytes in [
            b"id: 1\n\n".as_slice(),
            b"event: delivery\ndata: {}\ndata: {}\n\n",
        ] {
            assert!(SseDecoder::default().push(bytes).is_err());
        }

        let mut decoder = SseDecoder::default();
        assert_eq!(
            decoder
                .push(b"event: terminal\ndata: {\"transportVersion\":1,\"code\":\"done\"}\n\n")
                .expect("terminal"),
            vec![RawSseFrame::Terminal(
                br#"{"transportVersion":1,"code":"done"}"#.to_vec()
            )]
        );
        assert_eq!(
            decoder.push(b": ping\n\n"),
            Err(SseDecodeError::DataAfterTerminal)
        );
    }

    #[test]
    fn rejects_nul_invalid_line_ending_and_oversized_frame() {
        assert_eq!(
            SseDecoder::default().push(b"event: delivery\0\n\n"),
            Err(SseDecodeError::Nul)
        );
        assert_eq!(
            SseDecoder::default().push(b"event: delivery\rdata: {}\n\n"),
            Err(SseDecodeError::InvalidLineEnding)
        );
        let oversized = vec![b'x'; MAXIMUM_SSE_FRAME_BYTES + 1];
        assert_eq!(
            SseDecoder::default().push(&oversized),
            Err(SseDecodeError::FrameTooLarge)
        );
    }
}
