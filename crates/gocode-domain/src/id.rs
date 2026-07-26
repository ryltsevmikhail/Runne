//! Domain identifier newtypes — UUIDv7-based aggregate IDs,
//! bounded strings, integrity digests.

use core::fmt;
use std::str::FromStr;

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
    InvalidUuidVersion { expected: u8, actual: u8 },
    /// The UUID variant field is not RFC 9562 variant `10xx`.
    InvalidUuidVariant,
    /// A bounded string exceeded its maximum byte length.
    TooLong { max: usize, actual: usize },
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
                write!(f, "value exceeds maximum length: max={}, actual={}", max, actual)
            }
        }
    }
}

impl std::error::Error for InvalidIdReason {}

// ── UUIDv7 helper ──────────────────────────────────────────────────────────

/// Parse a UUIDv7 string into `[u8; 16]`, validating format, version (7),
/// and variant (`10xx`).
///
/// No external dependencies — manual hex parsing.
fn parse_uuid_v7(s: &str) -> Result<[u8; 16], InvalidIdReason> {
    if s.is_empty() {
        return Err(InvalidIdReason::Empty);
    }
    if s.len() != 36 {
        return Err(InvalidIdReason::InvalidUuidFormat);
    }
    let b = s.as_bytes();
    // Check hyphens at positions 8, 13, 18, 23
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return Err(InvalidIdReason::InvalidUuidFormat);
    }
    // Parse 32 hex nibbles → 16 bytes
    let mut out = [0u8; 16];
    let mut byte_idx = 0usize;
    let mut chars = s.chars().filter(|c| *c != '-');
    while byte_idx < 16 {
        let hi = chars.next().unwrap();
        let lo = chars.next().unwrap();
        let hi_val = hex_nibble(hi as u8).ok_or(InvalidIdReason::InvalidUuidFormat)?;
        let lo_val = hex_nibble(lo as u8).ok_or(InvalidIdReason::InvalidUuidFormat)?;
        out[byte_idx] = (hi_val << 4) | lo_val;
        byte_idx += 1;
    }
    // Version: upper nibble of byte 6 must be 0x7
    let version = out[6] >> 4;
    if version != 7 {
        return Err(InvalidIdReason::InvalidUuidVersion {
            expected: 7,
            actual: version,
        });
    }
    // Variant: top 2 bits of byte 8 must be 0b10
    let variant = out[8] >> 6;
    if variant != 0b10 {
        return Err(InvalidIdReason::InvalidUuidVariant);
    }
    Ok(out)
}

/// Interpret a byte as a hex nibble value.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Format a `[u8; 16]` as a standard 8-4-4-4-12 UUID string.
fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],
        bytes[6],  bytes[7],
        bytes[8],  bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ── Macro for UUIDv7 newtype generation ────────────────────────────────────

macro_rules! uuid_v7_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Create from raw bytes. Caller must ensure bytes are a valid UUIDv7.
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Return a reference to the raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Consume and return the raw bytes.
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
            type Err = InvalidIdReason;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = parse_uuid_v7(s)?;
                Ok(Self(bytes))
            }
        }
    };
}

// ── UUIDv7 newtypes ────────────────────────────────────────────────────────

uuid_v7_newtype!(TaskRunId, "UUIDv7 identifier for a task run aggregate.");
uuid_v7_newtype!(ConversationId, "UUIDv7 identifier for a conversation aggregate.");
uuid_v7_newtype!(WorkspaceId, "UUIDv7 identifier for a workspace aggregate.");
uuid_v7_newtype!(AttemptId, "UUIDv7 identifier for a single execution attempt.");
uuid_v7_newtype!(InvocationId, "UUIDv7 identifier for a plugin invocation.");
uuid_v7_newtype!(CheckpointId, "UUIDv7 identifier for a checkpoint.");
uuid_v7_newtype!(PolicyId, "UUIDv7 identifier for a policy.");
uuid_v7_newtype!(ProcessId, "UUIDv7 identifier for a host process.");
uuid_v7_newtype!(EventId, "UUIDv7 identifier for a domain event.");
uuid_v7_newtype!(CommandId, "UUIDv7 identifier for a command.");

// ── IdempotencyKey ────────────────────────────────────────────────────────

/// Opaque client-provided idempotency key.
///
/// Bounded by `MAX_IDEMPOTENCY_KEY_BYTES` (256). Must not contain NUL bytes
/// or ASCII control characters (0x00–0x1F, 0x7F).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Create a new `IdempotencyKey` from a string, validating bounds
    /// and character constraints.
    pub fn new(s: impl Into<String>) -> Result<Self, InvalidIdReason> {
        let s = s.into();
        if s.is_empty() {
            return Err(InvalidIdReason::Empty);
        }
        let len = s.len();
        if len > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(InvalidIdReason::TooLong {
                max: MAX_IDEMPOTENCY_KEY_BYTES,
                actual: len,
            });
        }
        if s.as_bytes().iter().any(|&b| b < 0x20 || b == 0x7f) {
            return Err(InvalidIdReason::InvalidUuidFormat); // best proxy — malformed identifier
        }
        Ok(Self(s))
    }

    /// Return a reference to the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── IntegrityDigest ────────────────────────────────────────────────────────

/// SHA-256 integrity digest (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntegrityDigest([u8; 32]);

impl IntegrityDigest {
    /// Create from raw 32-byte digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return a reference to the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume and return raw bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for IntegrityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ── AggregateId ────────────────────────────────────────────────────────────

use crate::event::AggregateType;

/// Typed aggregate identifier — disambiguates aggregates of different types
/// that happen to share the same UUIDv7 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AggregateId {
    /// A `TaskRun` aggregate.
    TaskRun(TaskRunId),
    /// A `Conversation` aggregate.
    Conversation(ConversationId),
    /// A `Workspace` aggregate.
    Workspace(WorkspaceId),
}

impl AggregateId {
    /// Return the [`AggregateType`] discriminant.
    pub fn aggregate_type(&self) -> AggregateType {
        match self {
            Self::TaskRun(_) => AggregateType::TaskRun,
            Self::Conversation(_) => AggregateType::Conversation,
            Self::Workspace(_) => AggregateType::Workspace,
        }
    }
}

impl fmt::Display for AggregateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskRun(id) => write!(f, "taskrun:{}", id),
            Self::Conversation(id) => write!(f, "conversation:{}", id),
            Self::Workspace(id) => write!(f, "workspace:{}", id),
        }
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // valid UUIDv7: version nibble = 7, variant = 10xx
    const VALID_UUID_V7: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_parse_uuid_v7_valid() {
        let bytes = parse_uuid_v7(VALID_UUID_V7).unwrap();
        // version nibble
        assert_eq!(bytes[6] >> 4, 7);
        // variant
        assert_eq!(bytes[8] >> 6, 0b10);
    }

    #[test]
    fn test_parse_uuid_v7_empty() {
        assert_eq!(parse_uuid_v7(""), Err(InvalidIdReason::Empty));
    }

    #[test]
    fn test_parse_uuid_v7_wrong_length() {
        assert_eq!(
            parse_uuid_v7("too-short"),
            Err(InvalidIdReason::InvalidUuidFormat)
        );
    }

    #[test]
    fn test_parse_uuid_v7_wrong_hyphens() {
        // missing hyphens
        assert_eq!(
            parse_uuid_v7("018f2e3a70007000800000000000000000"),
            Err(InvalidIdReason::InvalidUuidFormat)
        );
    }

    #[test]
    fn test_parse_uuid_v7_wrong_version() {
        // UUIDv4 byte 6 nibble = 4
        let v4 = "018f2e3a-7000-4000-8000-000000000000";
        assert_eq!(
            parse_uuid_v7(v4),
            Err(InvalidIdReason::InvalidUuidVersion {
                expected: 7,
                actual: 4
            })
        );
    }

    #[test]
    fn test_parse_uuid_v7_wrong_variant() {
        // variant 0b00
        let bad_variant = "018f2e3a-7000-7000-0000-000000000000";
        assert_eq!(
            parse_uuid_v7(bad_variant),
            Err(InvalidIdReason::InvalidUuidVariant)
        );
    }

    #[test]
    fn test_parse_uuid_v7_invalid_hex() {
        assert_eq!(
            parse_uuid_v7("018f2e3a-7000-7000-8000-00000000000g"),
            Err(InvalidIdReason::InvalidUuidFormat)
        );
    }

    #[test]
    fn test_taskrun_id_from_str_and_display_roundtrip() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        assert_eq!(id.to_string(), VALID_UUID_V7);
    }

    #[test]
    fn test_all_newtypes_parse_identical_uuid() {
        let _: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let _: ConversationId = VALID_UUID_V7.parse().unwrap();
        let _: WorkspaceId = VALID_UUID_V7.parse().unwrap();
        let _: AttemptId = VALID_UUID_V7.parse().unwrap();
        let _: InvocationId = VALID_UUID_V7.parse().unwrap();
        let _: CheckpointId = VALID_UUID_V7.parse().unwrap();
        let _: PolicyId = VALID_UUID_V7.parse().unwrap();
        let _: ProcessId = VALID_UUID_V7.parse().unwrap();
        let _: EventId = VALID_UUID_V7.parse().unwrap();
        let _: CommandId = VALID_UUID_V7.parse().unwrap();
    }

    #[test]
    fn test_newtypes_copy_and_eq() {
        let a: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn test_newtypes_ord() {
        let a: TaskRunId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
        let b: TaskRunId = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
        assert!(a < b);
    }

    #[test]
    fn test_newtypes_hash() {
        use std::collections::HashSet;
        let a: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let b: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn test_newtype_debug() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let debug = format!("{:?}", id);
        assert!(debug.contains("TaskRunId"));
        assert!(debug.contains(VALID_UUID_V7));
    }

    #[test]
    fn test_idempotency_key_valid() {
        let key = IdempotencyKey::new("req-001").unwrap();
        assert_eq!(key.as_str(), "req-001");
        assert_eq!(key.to_string(), "req-001");
    }

    #[test]
    fn test_idempotency_key_empty() {
        assert_eq!(IdempotencyKey::new(""), Err(InvalidIdReason::Empty));
    }

    #[test]
    fn test_idempotency_key_too_long() {
        let long = "x".repeat(257);
        assert_eq!(
            IdempotencyKey::new(long),
            Err(InvalidIdReason::TooLong {
                max: 256,
                actual: 257
            })
        );
    }

    #[test]
    fn test_idempotency_key_control_char() {
        // NUL byte
        assert!(IdempotencyKey::new("req\u{0000}").is_err());
    }

    #[test]
    fn test_idempotency_key_clone_eq_hash() {
        use std::collections::HashSet;
        let k1 = IdempotencyKey::new("abc").unwrap();
        let k2 = IdempotencyKey::new("abc").unwrap();
        assert_eq!(k1, k2);
        let mut set = HashSet::new();
        set.insert(k1.clone());
        assert!(set.contains(&k2));
    }

    #[test]
    fn test_integrity_digest_display() {
        let digest = IntegrityDigest::from_bytes([0xab; 32]);
        let s = digest.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_aggregate_id_aggregate_type() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let agg = AggregateId::TaskRun(id);
        assert_eq!(agg.aggregate_type(), AggregateType::TaskRun);
    }

    #[test]
    fn test_aggregate_id_display() {
        let id: TaskRunId = VALID_UUID_V7.parse().unwrap();
        let display = AggregateId::TaskRun(id).to_string();
        assert!(display.starts_with("taskrun:"));
    }
}
