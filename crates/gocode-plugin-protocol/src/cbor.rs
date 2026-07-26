//! Deterministic CBOR codec — RFC 8949 Core Deterministic Encoding subset.
//!
//! Supported: unsigned int, negative int, byte string, text string, array, map,
//! simple values (false, true, null).
//!
//! Rejected: floats (major 7 values 25-27), tags (major 6), indefinite-length,
//! other simple values, non-canonical integer encodings.

use core::fmt;

use crate::id::MessageTypeId;
use crate::profile::DecodeLimits;

// ── MajorType ──────────────────────────────────────────────────────────────

/// CBOR major type (bits 7-5 of initial byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MajorType {
    Unsigned = 0,
    Negative = 1,
    ByteString = 2,
    TextString = 3,
    Array = 4,
    Map = 5,
    Simple = 7,
}

impl MajorType {
    fn from_byte(b: u8) -> Self {
        match b >> 5 {
            0 => Self::Unsigned,
            1 => Self::Negative,
            2 => Self::ByteString,
            3 => Self::TextString,
            4 => Self::Array,
            5 => Self::Map,
            7 => Self::Simple,
            _ => Self::Simple, // major 6 (tag) handled as error in decoder
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Negative => "negative",
            Self::ByteString => "byte string",
            Self::TextString => "text string",
            Self::Array => "array",
            Self::Map => "map",
            Self::Simple => "simple",
        }
    }
}

// ── EncodeError ───────────────────────────────────────────────────────────

/// Error produced during deterministic CBOR encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Value exceeds the allowed range.
    ValueOutOfRange { min: i64, max: i64, actual: i64 },
    /// Encoded frame exceeds size limit.
    FrameTooLarge { max: usize, actual: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueOutOfRange { min, max, actual } => {
                write!(f, "value {} out of range [{}, {}]", actual, min, max)
            }
            Self::FrameTooLarge { max, actual } => {
                write!(f, "encoded frame too large: max={}, actual={}", max, actual)
            }
        }
    }
}

impl std::error::Error for EncodeError {}

// ── DecodeError ───────────────────────────────────────────────────────────

/// Error produced during deterministic CBOR decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Non-canonical encoding detected (e.g. zero-padded integer).
    NonCanonicalEncoding { offset: usize },
    /// Unknown map key encountered.
    UnknownField { key: u64 },
    /// Unexpected major type at offset.
    UnexpectedMajorType { offset: usize, expected: MajorType, actual: MajorType },
    /// A limit was exceeded.
    LimitExceeded { limit: String, max: usize, actual: usize },
    /// Duplicate key in map.
    DuplicateMapKey { key: u64 },
    /// Invalid UTF-8 in text string.
    InvalidUtf8 { offset: usize },
    /// Unsupported simple value.
    UnsupportedSimpleValue { value: u8 },
    /// Required map key not present.
    MissingRequiredField { key: u64 },
    /// Unknown message type ID during bootstrap decode.
    UnknownMessageType { type_id: u32 },
    /// Frame exceeds maximum size.
    FrameTooLarge { max: usize, actual: usize },
    /// Frame truncated (fewer bytes than length prefix indicates).
    FrameTruncated { expected: usize, actual: usize },
    /// CBOR data truncated mid-item.
    TruncatedCbor { offset: usize },
    /// Trailing bytes after frame or CBOR item.
    TrailingBytes { offset: usize, count: usize },
    /// Re-encode produced different bytes than input (non-deterministic).
    ReencodeMismatch { offset: usize },
    /// Invalid UUID variant in byte string.
    InvalidUuidVariant { offset: usize },
    /// Float values are not allowed.
    FloatNotAllowed { offset: usize },
    /// Tag (major 6) is not allowed.
    TagNotAllowed { offset: usize, tag: u64 },
    /// Indefinite-length items not allowed.
    IndefiniteLengthNotAllowed { offset: usize },
    /// Duplicate field (encoder-level check, separate from map key check).
    DuplicateField { key: u64 },
    /// String exceeds maximum byte length.
    StringTooLong { offset: usize, max: usize, actual: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalEncoding { offset } => write!(f, "non-canonical encoding at offset {}", offset),
            Self::UnknownField { key } => write!(f, "unknown field key {}", key),
            Self::UnexpectedMajorType { offset, expected, actual } => {
                write!(f, "expected {} at offset {}, got {}", expected.name(), offset, actual.name())
            }
            Self::LimitExceeded { limit, max, actual } => {
                write!(f, "{} limit exceeded: max={}, actual={}", limit, max, actual)
            }
            Self::DuplicateMapKey { key } => write!(f, "duplicate map key {}", key),
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at offset {}", offset),
            Self::UnsupportedSimpleValue { value } => write!(f, "unsupported simple value {}", value),
            Self::MissingRequiredField { key } => write!(f, "missing required field {}", key),
            Self::UnknownMessageType { type_id } => write!(f, "unknown message type {}", type_id),
            Self::FrameTooLarge { max, actual } => write!(f, "frame too large: max={}, actual={}", max, actual),
            Self::FrameTruncated { expected, actual } => write!(f, "frame truncated: expected={}, actual={}", expected, actual),
            Self::TruncatedCbor { offset } => write!(f, "truncated CBOR at offset {}", offset),
            Self::TrailingBytes { offset, count } => write!(f, "{} trailing bytes at offset {}", count, offset),
            Self::ReencodeMismatch { offset } => write!(f, "re-encode mismatch at offset {}", offset),
            Self::InvalidUuidVariant { offset } => write!(f, "invalid UUID variant at offset {}", offset),
            Self::FloatNotAllowed { offset } => write!(f, "float not allowed at offset {}", offset),
            Self::TagNotAllowed { offset, tag } => write!(f, "tag {} not allowed at offset {}", tag, offset),
            Self::IndefiniteLengthNotAllowed { offset } => write!(f, "indefinite length not allowed at offset {}", offset),
            Self::DuplicateField { key } => write!(f, "duplicate field key {}", key),
            Self::StringTooLong { offset, max, actual } => write!(f, "string too long at offset {}: max={}, actual={}", offset, max, actual),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── CborEncoder ───────────────────────────────────────────────────────────

/// Deterministic CBOR encoder.
///
/// Produces RFC 8949 Core Deterministic Encoding:
/// - Integers use shortest form
/// - Map keys encoded in bytewise lexicographic order (caller sorts before writing)
/// - No floats, tags, or indefinite-length
#[derive(Debug)]
pub struct CborEncoder {
    buf: Vec<u8>,
}

impl CborEncoder {
    pub fn new() -> Self { Self { buf: Vec::new() } }
    pub fn with_capacity(cap: usize) -> Self { Self { buf: Vec::with_capacity(cap) } }
    pub fn as_bytes(&self) -> &[u8] { &self.buf }
    pub fn into_bytes(self) -> Vec<u8> { self.buf }
    pub fn len(&self) -> usize { self.buf.len() }

    fn write_initial_byte(&mut self, major: u8, additional: u8) {
        self.buf.push((major << 5) | (additional & 0x1f));
    }

    fn write_argument(&mut self, arg: u64) {
        // Deterministic: use shortest encoding
        if arg <= 23 {
            self.buf.last_mut().map(|b| *b |= arg as u8);
        } else if arg <= 0xFF {
            self.buf.last_mut().map(|b| *b |= 24);
            self.buf.push(arg as u8);
        } else if arg <= 0xFFFF {
            self.buf.last_mut().map(|b| *b |= 25);
            self.buf.extend_from_slice(&(arg as u16).to_be_bytes());
        } else if arg <= 0xFFFF_FFFF {
            self.buf.last_mut().map(|b| *b |= 26);
            self.buf.extend_from_slice(&(arg as u32).to_be_bytes());
        } else {
            self.buf.last_mut().map(|b| *b |= 27);
            self.buf.extend_from_slice(&arg.to_be_bytes());
        }
    }

    pub fn write_unsigned(&mut self, value: u64) {
        self.write_initial_byte(0, 0);
        self.write_argument(value);
    }

    pub fn write_negative(&mut self, value: i64) {
        assert!(value < 0, "use write_unsigned for non-negative values");
        let n = (-value - 1) as u64;
        self.write_initial_byte(1, 0);
        self.write_argument(n);
    }

    pub fn write_byte_string(&mut self, data: &[u8]) {
        let len = data.len() as u64;
        self.write_initial_byte(2, 0);
        self.write_argument(len);
        self.buf.extend_from_slice(data);
    }

    pub fn write_text_string(&mut self, text: &str) {
        let len = text.len() as u64;
        self.write_initial_byte(3, 0);
        self.write_argument(len);
        self.buf.extend_from_slice(text.as_bytes());
    }

    pub fn write_array_header(&mut self, len: u64) {
        self.write_initial_byte(4, 0);
        self.write_argument(len);
    }

    pub fn write_map_header(&mut self, len: u64) {
        self.write_initial_byte(5, 0);
        self.write_argument(len);
    }

    pub fn write_bool(&mut self, value: bool) {
        if value {
            self.buf.push(0xf5);
        } else {
            self.buf.push(0xf4);
        }
    }

    pub fn write_null(&mut self) {
        self.buf.push(0xf6);
    }

    /// Write a 16-byte UUID as a tagged byte string.
    pub fn write_uuid_bytes(&mut self, bytes: &[u8; 16]) {
        self.write_byte_string(bytes);
    }
}

// ── CborDecoder ───────────────────────────────────────────────────────────

/// Deterministic CBOR decoder with bounds checking.
pub struct CborDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    fn remaining(&self) -> usize { self.data.len() - self.pos }
    fn peek(&self) -> Result<u8, DecodeError> {
        self.data.get(self.pos).copied().ok_or(DecodeError::TruncatedCbor { offset: self.pos })
    }
    fn advance(&mut self, n: usize) { self.pos += n; }

    fn read_initial(&mut self, expected_major: MajorType) -> Result<(u8, u64), DecodeError> {
        let b = self.peek()?;
        let major = MajorType::from_byte(b);
        if major != expected_major {
            return Err(DecodeError::UnexpectedMajorType {
                offset: self.pos,
                expected: expected_major,
                actual: major,
            });
        }
        let additional = b & 0x1f;
        let value = self.read_argument(additional)?;
        Ok((additional, value))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, DecodeError> {
        self.advance(1);
        Ok(match additional {
            0..=23 => additional as u64,
            24 => {
                if self.remaining() < 1 { return Err(DecodeError::TruncatedCbor { offset: self.pos }); }
                // Deterministic: value >= 24 must not fit in <24
                let v = self.data[self.pos] as u64;
                if v < 24 { return Err(DecodeError::NonCanonicalEncoding { offset: self.pos }); }
                self.advance(1);
                v
            }
            25 => {
                if self.remaining() < 2 { return Err(DecodeError::TruncatedCbor { offset: self.pos }); }
                let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]) as u64;
                if v <= 0xFF { return Err(DecodeError::NonCanonicalEncoding { offset: self.pos }); }
                self.advance(2);
                v
            }
            26 => {
                if self.remaining() < 4 { return Err(DecodeError::TruncatedCbor { offset: self.pos }); }
                let v = u32::from_be_bytes([
                    self.data[self.pos], self.data[self.pos + 1],
                    self.data[self.pos + 2], self.data[self.pos + 3],
                ]) as u64;
                if v <= 0xFFFF { return Err(DecodeError::NonCanonicalEncoding { offset: self.pos }); }
                self.advance(4);
                v
            }
            27 => {
                if self.remaining() < 8 { return Err(DecodeError::TruncatedCbor { offset: self.pos }); }
                let v = u64::from_be_bytes([
                    self.data[self.pos], self.data[self.pos + 1],
                    self.data[self.pos + 2], self.data[self.pos + 3],
                    self.data[self.pos + 4], self.data[self.pos + 5],
                    self.data[self.pos + 6], self.data[self.pos + 7],
                ]);
                if v <= 0xFFFF_FFFF { return Err(DecodeError::NonCanonicalEncoding { offset: self.pos }); }
                self.advance(8);
                v
            }
            28..=30 => return Err(DecodeError::IndefiniteLengthNotAllowed { offset: self.pos - 1 }),
            31 => return Err(DecodeError::IndefiniteLengthNotAllowed { offset: self.pos - 1 }),
            _ => unreachable!(),
        })
    }

    pub fn read_unsigned(&mut self, max: u64) -> Result<u64, DecodeError> {
        let (_add, value) = self.read_initial(MajorType::Unsigned)?;
        if value > max {
            return Err(DecodeError::LimitExceeded {
                limit: "unsigned".into(), max: max as usize, actual: value as usize,
            });
        }
        Ok(value)
    }

    pub fn read_signed(&mut self, min: i64, max: i64) -> Result<i64, DecodeError> {
        let b = self.peek()?;
        match MajorType::from_byte(b) {
            MajorType::Unsigned => {
                let v = self.read_unsigned(max as u64)?;
                if v > max as u64 {
                    return Err(DecodeError::LimitExceeded {
                        limit: "signed".into(), max: max as usize, actual: v as usize,
                    });
                }
                Ok(v as i64)
            }
            MajorType::Negative => {
                let (_add, value) = self.read_initial(MajorType::Negative)?;
                let v = -((value as i64) + 1);
                if v < min {
                    return Err(DecodeError::LimitExceeded {
                        limit: "signed".into(), max: max as usize, actual: v as usize,
                    });
                }
                Ok(v)
            }
            other => Err(DecodeError::UnexpectedMajorType {
                offset: self.pos, expected: MajorType::Unsigned, actual: other,
            }),
        }
    }

    pub fn read_byte_string(&mut self, max_bytes: usize) -> Result<&'a [u8], DecodeError> {
        let offset = self.pos;
        let (_add, len) = self.read_initial(MajorType::ByteString)?;
        if len as usize > max_bytes {
            return Err(DecodeError::StringTooLong { offset, max: max_bytes, actual: len as usize });
        }
        if self.remaining() < len as usize {
            return Err(DecodeError::TruncatedCbor { offset: self.pos });
        }
        let start = self.pos;
        self.advance(len as usize);
        Ok(&self.data[start..start + len as usize])
    }

    pub fn read_text_string(&mut self, max_bytes: usize) -> Result<&'a str, DecodeError> {
        let offset = self.pos;
        let (_add, len) = self.read_initial(MajorType::TextString)?;
        if len as usize > max_bytes {
            return Err(DecodeError::StringTooLong { offset, max: max_bytes, actual: len as usize });
        }
        if self.remaining() < len as usize {
            return Err(DecodeError::TruncatedCbor { offset: self.pos });
        }
        let start = self.pos;
        self.advance(len as usize);
        let bytes = &self.data[start..start + len as usize];
        std::str::from_utf8(bytes)
            .map_err(|_| DecodeError::InvalidUtf8 { offset })
    }

    pub fn read_array_header(&mut self, max_items: u32) -> Result<u64, DecodeError> {
        let (_add, len) = self.read_initial(MajorType::Array)?;
        if len > max_items as u64 {
            return Err(DecodeError::LimitExceeded {
                limit: "array items".into(), max: max_items as usize, actual: len as usize,
            });
        }
        Ok(len)
    }

    pub fn read_map_header(&mut self, max_items: u32) -> Result<u64, DecodeError> {
        let (_add, len) = self.read_initial(MajorType::Map)?;
        if len > max_items as u64 {
            return Err(DecodeError::LimitExceeded {
                limit: "map items".into(), max: max_items as usize, actual: len as usize,
            });
        }
        Ok(len)
    }

    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        let b = self.peek()?;
        match b {
            0xf4 => { self.advance(1); Ok(false) }
            0xf5 => { self.advance(1); Ok(true) }
            _ => Err(DecodeError::UnexpectedMajorType {
                offset: self.pos, expected: MajorType::Simple, actual: MajorType::from_byte(b),
            }),
        }
    }

    pub fn read_null(&mut self) -> Result<(), DecodeError> {
        let b = self.peek()?;
        if b == 0xf6 { self.advance(1); Ok(()) }
        else {
            Err(DecodeError::UnexpectedMajorType {
                offset: self.pos, expected: MajorType::Simple, actual: MajorType::from_byte(b),
            })
        }
    }

    pub fn read_optional_bool(&mut self) -> Result<Option<bool>, DecodeError> {
        let b = self.peek()?;
        match b {
            0xf4 => { self.advance(1); Ok(Some(false)) }
            0xf5 => { self.advance(1); Ok(Some(true)) }
            0xf6 => { self.advance(1); Ok(None) }
            _ => Err(DecodeError::UnexpectedMajorType {
                offset: self.pos, expected: MajorType::Simple, actual: MajorType::from_byte(b),
            }),
        }
    }

    pub fn read_uuid_bytes(&mut self) -> Result<[u8; 16], DecodeError> {
        let bytes = self.read_byte_string(16)?;
        if bytes.len() != 16 {
            return Err(DecodeError::TruncatedCbor { offset: self.pos });
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Check for major type 6 (tag) at current position.
    pub fn reject_tags(&mut self) -> Result<(), DecodeError> {
        let b = self.peek()?;
        if MajorType::from_byte(b) as u8 == 6 {
            return Err(DecodeError::TagNotAllowed { offset: self.pos, tag: 0 });
        }
        Ok(())
    }

    /// Check the current offset is at the end of the buffer.
    pub fn expect_eof(&self) -> Result<(), DecodeError> {
        if self.pos < self.data.len() {
            return Err(DecodeError::TrailingBytes { offset: self.pos, count: self.data.len() - self.pos });
        }
        Ok(())
    }

    /// Current byte offset.
    pub fn position(&self) -> usize { self.pos }
}

// ── DeterministicCodec trait ──────────────────────────────────────────────

/// Types that can be deterministically encoded/decoded as CBOR.
pub trait DeterministicCodec: Sized {
    /// The registered message type ID for this type.
    const MESSAGE_TYPE_ID: u32;

    /// Encode `self` into the encoder.
    fn encode(&self, enc: &mut CborEncoder) -> Result<(), EncodeError>;

    /// Decode `Self` from the decoder. `type_id` is the wire type ID
    /// and must match `MESSAGE_TYPE_ID`.
    fn decode(type_id: u32, dec: &mut CborDecoder) -> Result<Self, DecodeError>;
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Encoder tests ───────────────────────────────────────────────────

    #[test]
    fn test_encode_unsigned_zero() {
        let mut e = CborEncoder::new();
        e.write_unsigned(0);
        assert_eq!(e.into_bytes(), vec![0x00]);
    }

    #[test]
    fn test_encode_unsigned_23() {
        let mut e = CborEncoder::new();
        e.write_unsigned(23);
        assert_eq!(e.into_bytes(), vec![0x17]);
    }

    #[test]
    fn test_encode_unsigned_24() {
        let mut e = CborEncoder::new();
        e.write_unsigned(24);
        assert_eq!(e.into_bytes(), vec![0x18, 0x18]);
    }

    #[test]
    fn test_encode_unsigned_256() {
        let mut e = CborEncoder::new();
        e.write_unsigned(256);
        assert_eq!(e.into_bytes(), vec![0x19, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_negative_minus_1() {
        let mut e = CborEncoder::new();
        e.write_negative(-1);
        assert_eq!(e.into_bytes(), vec![0x20]);
    }

    #[test]
    fn test_encode_byte_string() {
        let mut e = CborEncoder::new();
        e.write_byte_string(b"hello");
        assert_eq!(e.into_bytes(), vec![0x45, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_encode_text_string() {
        let mut e = CborEncoder::new();
        e.write_text_string("hi");
        assert_eq!(e.into_bytes(), vec![0x62, b'h', b'i']);
    }

    #[test]
    fn test_encode_array() {
        let mut e = CborEncoder::new();
        e.write_array_header(2);
        e.write_unsigned(1);
        e.write_unsigned(2);
        assert_eq!(e.into_bytes(), vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn test_encode_map() {
        let mut e = CborEncoder::new();
        e.write_map_header(1);
        e.write_unsigned(1);
        e.write_text_string("v");
        assert_eq!(e.into_bytes(), vec![0xA1, 0x01, 0x61, b'v']);
    }

    #[test]
    fn test_encode_bool_and_null() {
        let mut e = CborEncoder::new();
        e.write_bool(true);
        e.write_bool(false);
        e.write_null();
        assert_eq!(e.into_bytes(), vec![0xf5, 0xf4, 0xf6]);
    }

    // ─── Decoder tests ───────────────────────────────────────────────────

    #[test]
    fn test_decode_unsigned_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_unsigned(42);
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_unsigned(100).unwrap(), 42);
        d.expect_eof().unwrap();
    }

    #[test]
    fn test_decode_string_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_text_string("hello");
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_text_string(100).unwrap(), "hello");
        d.expect_eof().unwrap();
    }

    #[test]
    fn test_decode_byte_string_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_byte_string(&[1, 2, 3]);
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_byte_string(100).unwrap(), &[1, 2, 3]);
        d.expect_eof().unwrap();
    }

    #[test]
    fn test_decode_array_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_array_header(3);
        e.write_unsigned(10);
        e.write_unsigned(20);
        e.write_unsigned(30);
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_array_header(10).unwrap(), 3);
        assert_eq!(d.read_unsigned(100).unwrap(), 10);
        assert_eq!(d.read_unsigned(100).unwrap(), 20);
        assert_eq!(d.read_unsigned(100).unwrap(), 30);
        d.expect_eof().unwrap();
    }

    // ─── Non-canonical rejection ─────────────────────────────────────────

    #[test]
    fn test_reject_non_canonical_unsigned() {
        // 0 encoded as 0x1800 (two bytes instead of one)
        let mut d = CborDecoder::new(&[0x18, 0x00]);
        assert!(matches!(d.read_unsigned(100), Err(DecodeError::NonCanonicalEncoding { .. })));
    }

    #[test]
    fn test_reject_truncated() {
        let mut d = CborDecoder::new(&[0x5A, 0x00]); // byte string header expecting 2 more bytes
        assert!(matches!(d.read_byte_string(100), Err(DecodeError::TruncatedCbor { .. })));
    }

    #[test]
    fn test_reject_trailing_bytes() {
        let mut e = CborEncoder::new();
        e.write_unsigned(1);
        let mut data = e.into_bytes();
        data.push(0x00); // trailing
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_unsigned(100).unwrap(), 1);
        assert!(matches!(d.expect_eof(), Err(DecodeError::TrailingBytes { .. })));
    }

    #[test]
    fn test_decode_bool() {
        let mut d = CborDecoder::new(&[0xf5]);
        assert_eq!(d.read_bool().unwrap(), true);
        let mut d = CborDecoder::new(&[0xf4]);
        assert_eq!(d.read_bool().unwrap(), false);
    }

    #[test]
    fn test_decode_null() {
        let mut d = CborDecoder::new(&[0xf6]);
        d.read_null().unwrap();
    }

    #[test]
    fn test_decode_map_then_keys() {
        let mut e = CborEncoder::new();
        e.write_map_header(2);
        e.write_unsigned(1);
        e.write_text_string("a");
        e.write_unsigned(2);
        e.write_text_string("b");
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_map_header(10).unwrap(), 2);
        assert_eq!(d.read_unsigned(10).unwrap(), 1);
        assert_eq!(d.read_text_string(10).unwrap(), "a");
        assert_eq!(d.read_unsigned(10).unwrap(), 2);
        assert_eq!(d.read_text_string(10).unwrap(), "b");
        d.expect_eof().unwrap();
    }
}
