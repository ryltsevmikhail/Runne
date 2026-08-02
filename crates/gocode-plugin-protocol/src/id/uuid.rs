/// Reason why a wire identifier was rejected during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidWireIdReason {
    /// Input is empty.
    Empty,
    /// Does not match UUID format (8-4-4-4-12 hex).
    InvalidUuidFormat,
    /// Wrong UUID version nibble.
    InvalidUuidVersion { expected: u8, actual: u8 },
    /// Wrong UUID variant (expected RFC 9562 `10xx`).
    InvalidUuidVariant,
    /// Bounded string exceeds maximum length.
    TooLong { max: usize, actual: usize },
    /// Contains control characters or is not ASCII printable.
    InvalidCharacter,
}

impl fmt::Display for InvalidWireIdReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "identifier is empty"),
            Self::InvalidUuidFormat => write!(f, "invalid UUID format"),
            Self::InvalidUuidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid UUID version: expected v{}, got v{}",
                    expected, actual
                )
            }
            Self::InvalidUuidVariant => write!(f, "invalid UUID variant"),
            Self::TooLong { max, actual } => {
                write!(f, "value too long: max={}, actual={}", max, actual)
            }
            Self::InvalidCharacter => write!(f, "invalid character in identifier"),
        }
    }
}

impl std::error::Error for InvalidWireIdReason {}

// ── UUIDv7 helpers (std-only, no uuid crate) ──────────────────────────────

fn parse_uuid_v7(s: &str) -> Result<[u8; 16], InvalidWireIdReason> {
    if s.is_empty() {
        return Err(InvalidWireIdReason::Empty);
    }
    if s.len() != 36 {
        return Err(InvalidWireIdReason::InvalidUuidFormat);
    }
    let b = s.as_bytes();
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return Err(InvalidWireIdReason::InvalidUuidFormat);
    }
    let mut out = [0u8; 16];
    let mut byte_idx = 0usize;
    let mut chars = s.chars().filter(|c| *c != '-');
    while byte_idx < 16 {
        let hi = chars.next().ok_or(InvalidWireIdReason::InvalidUuidFormat)?;
        let lo = chars.next().ok_or(InvalidWireIdReason::InvalidUuidFormat)?;
        let hi_val = hex_nibble(hi as u8).ok_or(InvalidWireIdReason::InvalidUuidFormat)?;
        let lo_val = hex_nibble(lo as u8).ok_or(InvalidWireIdReason::InvalidUuidFormat)?;
        out[byte_idx] = (hi_val << 4) | lo_val;
        byte_idx += 1;
    }
    let version = out[6] >> 4;
    if version != 7 {
        return Err(InvalidWireIdReason::InvalidUuidVersion {
            expected: 7,
            actual: version,
        });
    }
    if out[8] >> 6 != 0b10 {
        return Err(InvalidWireIdReason::InvalidUuidVariant);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

// ── UUIDv7 newtype macro ──────────────────────────────────────────────────

macro_rules! wire_uuid_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Create from raw 16-byte array.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }
            /// Borrow the inner 16-byte array.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
            /// Consume and return the inner 16-byte array.
            pub const fn into_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&format_uuid(&self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", format_uuid(&self.0))
            }
        }

        impl FromStr for $name {
            type Err = InvalidWireIdReason;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(parse_uuid_v7(s)?))
            }
        }
    };
}

// ── UUIDv7 wire newtypes ──────────────────────────────────────────────────

wire_uuid_newtype!(WireTaskRunId, "Wire-level task run identifier (UUIDv7).");
wire_uuid_newtype!(WireAttemptId, "Wire-level attempt identifier (UUIDv7).");
wire_uuid_newtype!(ProtocolSessionId, "Protocol session identifier (UUIDv7).");
wire_uuid_newtype!(RequestId, "Request correlation identifier (UUIDv7).");
wire_uuid_newtype!(InvocationId, "Invocation identifier (UUIDv7).");
wire_uuid_newtype!(
    ControlCorrelationId,
    "Control message correlation identifier (UUIDv7)."
);
wire_uuid_newtype!(ControlIntentId, "Control intent identifier (UUIDv7).");
