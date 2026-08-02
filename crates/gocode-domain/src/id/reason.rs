// ── constants ──────────────────────────────────────────────────────────────

/// Maximum bytes for an idempotency key (opaque client-provided).
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Maximum bytes for an actor identity string.
pub const MAX_ACTOR_BYTES: usize = 256;

/// Maximum bytes for an event type string.
pub const MAX_EVENT_TYPE_BYTES: usize = 128;

// ── InvalidIdReason ────────────────────────────────────────────────────────

/// Reason why an identifier string was rejected during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidIdReason {
    /// The input string is empty.
    Empty,
    /// The input does not match the UUID format (8-4-4-4-12 hex).
    InvalidUuidFormat,
    /// The UUID version field does not match the expected version.
    InvalidUuidVersion {
        /// The expected UUID version.
        expected: u8,
        /// The actual UUID version found.
        actual: u8,
    },
    /// The UUID variant field is not RFC 9562 variant `10xx`.
    InvalidUuidVariant,
    /// A bounded string exceeded its maximum byte length.
    TooLong {
        /// The maximum allowed byte length.
        max: usize,
        /// The actual byte length.
        actual: usize,
    },
}

impl fmt::Display for InvalidIdReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "identifier is empty"),
            Self::InvalidUuidFormat => {
                write!(f, "invalid UUID format (expected 8-4-4-4-12 hex digits)")
            }
            Self::InvalidUuidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid UUID version: expected v{}, got v{}",
                    expected, actual
                )
            }
            Self::InvalidUuidVariant => {
                write!(f, "invalid UUID variant (expected RFC 9562 variant 10xx)")
            }
            Self::TooLong { max, actual } => {
                write!(
                    f,
                    "value exceeds maximum length: max={}, actual={}",
                    max, actual
                )
            }
        }
    }
}

impl std::error::Error for InvalidIdReason {}
