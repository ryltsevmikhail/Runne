//! Frame codec — uint32_be length prefix + deterministic CBOR payload.
//!
//! Wire format: `uint32_be(length) || deterministic-CBOR(message)`.
//! Decode verifies re-encode byte equality (determinism check).

use crate::bootstrap::BootstrapMessage;
use crate::cbor::{CborDecoder, CborEncoder, DecodeError, DeterministicCodec, EncodeError};
use crate::profile::DecodeLimits;

/// Frame size limits for encoding.
pub struct FrameLimits {
    /// Maximum total frame bytes (including length prefix).
    pub max_frame_bytes: usize,
}

/// Encode a [`BootstrapMessage`] into a wire frame.
///
/// Returns the full frame: `uint32_be(payload_len) || deterministic-CBOR(payload)`.
pub fn encode_frame(
    message: &BootstrapMessage,
    limits: &FrameLimits,
) -> Result<Vec<u8>, EncodeError> {
    let mut enc = CborEncoder::new();
    message.encode(&mut enc)?;
    let payload = enc.into_bytes();

    // Length prefix (4 bytes) + payload
    let frame_len = payload
        .len()
        .checked_add(4)
        .ok_or(EncodeError::FrameTooLarge {
            max: limits.max_frame_bytes,
            actual: usize::MAX,
        })?;
    if frame_len > limits.max_frame_bytes {
        return Err(EncodeError::FrameTooLarge {
            max: limits.max_frame_bytes,
            actual: frame_len,
        });
    }

    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Encodes a profile-specific deterministic artifact into a bounded frame.
pub fn encode_codec_frame<T: DeterministicCodec>(
    message: &T,
    limits: &FrameLimits,
) -> Result<Vec<u8>, EncodeError> {
    let mut enc = CborEncoder::new();
    message.encode(&mut enc)?;
    let payload = enc.into_bytes();
    let frame_len = payload
        .len()
        .checked_add(4)
        .ok_or(EncodeError::FrameTooLarge {
            max: limits.max_frame_bytes,
            actual: usize::MAX,
        })?;
    if frame_len > limits.max_frame_bytes {
        return Err(EncodeError::FrameTooLarge {
            max: limits.max_frame_bytes,
            actual: frame_len,
        });
    }
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one profile-specific deterministic artifact from a bounded frame.
pub fn decode_codec_frame<T: DeterministicCodec>(
    data: &[u8],
    limits: &DecodeLimits,
) -> Result<T, DecodeError> {
    if data.len() >= 4 {
        let payload_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let frame_len = payload_len
            .checked_add(4)
            .ok_or(DecodeError::FrameTooLarge {
                max: limits.max_frame_bytes,
                actual: usize::MAX,
            })?;
        if frame_len != data.len() {
            return Err(DecodeError::FrameTruncated {
                expected: frame_len,
                actual: data.len(),
            });
        }
        if frame_len > limits.max_frame_bytes {
            return Err(DecodeError::FrameTooLarge {
                max: limits.max_frame_bytes,
                actual: frame_len,
            });
        }
        let mut decoder = CborDecoder::new(&data[4..]);
        let value = T::decode(T::MESSAGE_TYPE_ID, &mut decoder)?;
        decoder.expect_eof()?;
        let mut encoder = CborEncoder::new();
        value
            .encode(&mut encoder)
            .map_err(|_| DecodeError::ReencodeMismatch { offset: 0 })?;
        if encoder.into_bytes() != data[4..] {
            return Err(DecodeError::ReencodeMismatch { offset: 0 });
        }
        Ok(value)
    } else {
        Err(DecodeError::FrameTruncated {
            expected: 4,
            actual: data.len(),
        })
    }
}

/// Decode a wire frame into a [`BootstrapMessage`].
///
/// Full 3-stage decode:
/// 1. Read and validate uint32_be length prefix
/// 2. Deterministic CBOR decode
/// 3. Re-encode and check byte equality
pub fn decode_frame(data: &[u8], limits: &DecodeLimits) -> Result<BootstrapMessage, DecodeError> {
    if data.is_empty() {
        return Err(DecodeError::FrameTruncated {
            expected: 4,
            actual: 0,
        });
    }

    // Stage 1: Read length prefix
    if data.len() < 4 {
        return Err(DecodeError::FrameTruncated {
            expected: 4,
            actual: data.len(),
        });
    }
    let payload_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    let frame_total = payload_len
        .checked_add(4)
        .ok_or(DecodeError::FrameTooLarge {
            max: limits.max_frame_bytes,
            actual: usize::MAX,
        })?;
    if data.len() < frame_total {
        return Err(DecodeError::FrameTruncated {
            expected: frame_total,
            actual: data.len(),
        });
    }

    if frame_total > limits.max_frame_bytes as usize {
        return Err(DecodeError::FrameTooLarge {
            max: limits.max_frame_bytes as usize,
            actual: frame_total,
        });
    }

    // Trailing bytes check
    if data.len() > frame_total {
        return Err(DecodeError::TrailingBytes {
            offset: frame_total,
            count: data.len() - frame_total,
        });
    }

    let payload = &data[4..4 + payload_len];

    // Stage 2: Decode CBOR
    let mut dec = CborDecoder::new(payload);
    let message = BootstrapMessage::decode(BootstrapMessage::MESSAGE_TYPE_ID, &mut dec)?;
    dec.expect_eof()?;

    // Stage 3: Re-encode equality check
    let mut enc = CborEncoder::new();
    message
        .encode(&mut enc)
        .map_err(|_e| DecodeError::ReencodeMismatch { offset: 0 })?;
    let reencoded = enc.into_bytes();
    if reencoded != payload {
        return Err(DecodeError::ReencodeMismatch { offset: 0 });
    }

    Ok(message)
}

#[cfg(test)]
mod tests {
    include!("frame/tests.rs");
}
