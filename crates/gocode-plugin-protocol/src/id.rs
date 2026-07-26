//! Wire-level identifiers — independent of domain crates.
//!
//! All UUIDv7 newtypes, bounded strings, version/revision types,
//! and identifier-size constants.

use core::fmt;
use std::str::FromStr;

// ── Supporting types ───────────────────────────────────────────────────────

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
                write!(f, "invalid UUID version: expected v{}, got v{}", expected, actual)
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
        let hi = chars.next().unwrap();
        let lo = chars.next().unwrap();
        let hi_val = hex_nibble(hi as u8).ok_or(InvalidWireIdReason::InvalidUuidFormat)?;
        let lo_val = hex_nibble(lo as u8).ok_or(InvalidWireIdReason::InvalidUuidFormat)?;
        out[byte_idx] = (hi_val << 4) | lo_val;
        byte_idx += 1;
    }
    let version = out[6] >> 4;
    if version != 7 {
        return Err(InvalidWireIdReason::InvalidUuidVersion { expected: 7, actual: version });
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
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ── UUIDv7 newtype macro ──────────────────────────────────────────────────

macro_rules! wire_uuid_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self { Self(bytes) }
            pub const fn as_bytes(&self) -> &[u8; 16] { &self.0 }
            pub const fn into_bytes(self) -> [u8; 16] { self.0 }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&format_uuid(&self.0)).finish()
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
wire_uuid_newtype!(ControlCorrelationId, "Control message correlation identifier (UUIDv7).");
wire_uuid_newtype!(ControlIntentId, "Control intent identifier (UUIDv7).");

// ── Nonce ─────────────────────────────────────────────────────────────────

/// 16-byte random nonce for bootstrap handshake replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 16]);

impl Nonce {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self { Self(bytes) }
    pub const fn as_bytes(&self) -> &[u8; 16] { &self.0 }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 { write!(f, "{:02x}", b)?; }
        Ok(())
    }
}

// ── Bounded string newtype macro ──────────────────────────────────────────

macro_rules! bounded_id_string {
    ($name:ident, $max:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Max byte length.
            pub const MAX_BYTES: usize = $max;

            pub fn new(s: impl Into<String>) -> Result<Self, InvalidWireIdReason> {
                let s = s.into();
                if s.is_empty() { return Err(InvalidWireIdReason::Empty); }
                let len = s.len();
                if len > $max { return Err(InvalidWireIdReason::TooLong { max: $max, actual: len }); }
                if s.as_bytes().iter().any(|&b| b < 0x20 || b == 0x7f) {
                    return Err(InvalidWireIdReason::InvalidCharacter);
                }
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
        }
    };
}

bounded_id_string!(PluginId, 128, "Plugin package identity (e.g. 'com.example.my-plugin').");
bounded_id_string!(TargetIdentity, 128, "Target identity for plugin execution.");
bounded_id_string!(EntrypointIdentity, 256, "Entrypoint identity within a plugin.");
bounded_id_string!(PluginIdentity, 128, "Plugin runtime identity.");
bounded_id_string!(MigrationIdentity, 128, "Migration execution identity.");
bounded_id_string!(ProfileId, 128, "Protocol profile identifier.");
bounded_id_string!(PluginVersion, 64, "Plugin version string (semver).");

// ── ProtocolVersion ───────────────────────────────────────────────────────

/// Protocol version tuple. V1 begins at 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    pub const fn new(major: u16, minor: u16) -> Self { Self { major, minor } }
    pub const fn major(&self) -> u16 { self.major }
    pub const fn minor(&self) -> u16 { self.minor }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ── SchemaRevision / MessageTypeId / DeadlineUnixMillis ───────────────────

/// Monotonic schema revision number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaRevision(u32);

impl SchemaRevision {
    pub const fn new(v: u32) -> Self { Self(v) }
    pub const fn value(&self) -> u32 { self.0 }
}

impl fmt::Display for SchemaRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

/// Message type identifier — maps to a specific schema/type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageTypeId(u32);

impl MessageTypeId {
    pub const fn new(v: u32) -> Self { Self(v) }
    pub const fn value(&self) -> u32 { self.0 }
}

impl fmt::Display for MessageTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

/// Unix epoch milliseconds deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeadlineUnixMillis(u64);

impl DeadlineUnixMillis {
    pub const fn new(v: u64) -> Self { Self(v) }
    pub const fn value(&self) -> u64 { self.0 }
}

impl fmt::Display for DeadlineUnixMillis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_all_wire_uuids_parse() {
        let _: WireTaskRunId = VALID_UUID.parse().unwrap();
        let _: WireAttemptId = VALID_UUID.parse().unwrap();
        let _: ProtocolSessionId = VALID_UUID.parse().unwrap();
        let _: RequestId = VALID_UUID.parse().unwrap();
        let _: InvocationId = VALID_UUID.parse().unwrap();
        let _: ControlCorrelationId = VALID_UUID.parse().unwrap();
        let _: ControlIntentId = VALID_UUID.parse().unwrap();
    }

    #[test]
    fn test_wire_uuid_reject_wrong_version() {
        let v4 = "018f2e3a-7000-4000-8000-000000000000";
        assert!(v4.parse::<WireTaskRunId>().is_err());
    }

    #[test]
    fn test_nonce_display() {
        let n = Nonce::from_bytes([0xab; 16]);
        assert_eq!(n.to_string().len(), 32);
    }

    #[test]
    fn test_bounded_strings() {
        assert!(PluginId::new("my-plugin").is_ok());
        assert!(PluginId::new("").is_err());
        let too_long = "x".repeat(129);
        assert!(PluginId::new(too_long).is_err());
    }

    #[test]
    fn test_protocol_version() {
        assert_eq!(ProtocolVersion::V1_0.to_string(), "1.0");
        assert_eq!(ProtocolVersion::new(2, 1).to_string(), "2.1");
    }

    #[test]
    fn test_schema_revision() {
        let r = SchemaRevision::new(42);
        assert_eq!(r.value(), 42);
    }
}
