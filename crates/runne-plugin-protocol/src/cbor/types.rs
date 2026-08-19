use core::fmt;

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
    UnexpectedMajorType {
        offset: usize,
        expected: MajorType,
        actual: MajorType,
    },
    /// A limit was exceeded.
    LimitExceeded {
        limit: String,
        max: usize,
        actual: usize,
    },
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
    StringTooLong {
        offset: usize,
        max: usize,
        actual: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalEncoding { offset } => {
                write!(f, "non-canonical encoding at offset {}", offset)
            }
            Self::UnknownField { key } => write!(f, "unknown field key {}", key),
            Self::UnexpectedMajorType {
                offset,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "expected {} at offset {}, got {}",
                    expected.name(),
                    offset,
                    actual.name()
                )
            }
            Self::LimitExceeded { limit, max, actual } => {
                write!(
                    f,
                    "{} limit exceeded: max={}, actual={}",
                    limit, max, actual
                )
            }
            Self::DuplicateMapKey { key } => write!(f, "duplicate map key {}", key),
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at offset {}", offset),
            Self::UnsupportedSimpleValue { value } => {
                write!(f, "unsupported simple value {}", value)
            }
            Self::MissingRequiredField { key } => write!(f, "missing required field {}", key),
            Self::UnknownMessageType { type_id } => write!(f, "unknown message type {}", type_id),
            Self::FrameTooLarge { max, actual } => {
                write!(f, "frame too large: max={}, actual={}", max, actual)
            }
            Self::FrameTruncated { expected, actual } => write!(
                f,
                "frame truncated: expected={}, actual={}",
                expected, actual
            ),
            Self::TruncatedCbor { offset } => write!(f, "truncated CBOR at offset {}", offset),
            Self::TrailingBytes { offset, count } => {
                write!(f, "{} trailing bytes at offset {}", count, offset)
            }
            Self::ReencodeMismatch { offset } => {
                write!(f, "re-encode mismatch at offset {}", offset)
            }
            Self::InvalidUuidVariant { offset } => {
                write!(f, "invalid UUID variant at offset {}", offset)
            }
            Self::FloatNotAllowed { offset } => write!(f, "float not allowed at offset {}", offset),
            Self::TagNotAllowed { offset, tag } => {
                write!(f, "tag {} not allowed at offset {}", tag, offset)
            }
            Self::IndefiniteLengthNotAllowed { offset } => {
                write!(f, "indefinite length not allowed at offset {}", offset)
            }
            Self::DuplicateField { key } => write!(f, "duplicate field key {}", key),
            Self::StringTooLong {
                offset,
                max,
                actual,
            } => write!(
                f,
                "string too long at offset {}: max={}, actual={}",
                offset, max, actual
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── CborEncoder ───────────────────────────────────────────────────────────
