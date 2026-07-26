//! Protocol profile constants and decode limits.

use crate::digest::{
    BootstrapSchemaDigest, BoundsProfileDigest, ProfileDigest, SchemaBundleDigest,
    WireContractDigest,
};
use crate::id::{ProfileId, ProtocolVersion};

/// Decoding safety limits — cap wire sizes, nesting, and cardinalities.
///
/// Every CBOR decode operation is bounded by these limits.
/// Defaults are generous but safe for plugin protocol handshake
/// and bootstrap frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum unsigned integer value accepted during decode.
    pub max_unsigned: u64,
    /// Maximum signed integer value accepted during decode.
    pub max_signed: i64,
    /// Minimum signed integer value accepted during decode.
    pub min_signed: i64,
    /// Maximum byte length for byte strings and text strings (unified).
    pub max_string_bytes: usize,
    /// Maximum byte length for text strings.
    pub max_text_bytes: usize,
    /// Maximum byte length for byte strings.
    pub max_byte_string_bytes: usize,
    /// Maximum number of items in an array.
    pub max_array_items: u32,
    /// Maximum number of pairs in a map.
    pub max_map_items: u32,
    /// Maximum nesting depth for composite CBOR items.
    pub max_nesting_depth: u32,
    /// Maximum recursion depth for nested CBOR structures.
    pub max_recursion_depth: u32,
    /// Maximum frame size in bytes.
    pub max_frame_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_unsigned: u64::MAX,
            max_signed: i64::MAX,
            min_signed: i64::MIN,
            max_string_bytes: 64 * 1024, // 64 KiB
            max_text_bytes: 64 * 1024,
            max_byte_string_bytes: 64 * 1024,
            max_array_items: 1024,
            max_map_items: 256,
            max_nesting_depth: 16,
            max_recursion_depth: 16,
            max_frame_bytes: 1024 * 1024, // 1 MiB
        }
    }
}

// ── ProtocolProfileRef ────────────────────────────────────────────────────

/// Lightweight reference to a protocol profile: (id, digest).
///
/// Used in bootstrap handshake arrays to list supported profiles
/// without carrying full profile definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolProfileRef {
    profile_id: ProfileId,
    profile_digest: ProfileDigest,
}

impl ProtocolProfileRef {
    /// Create a new profile reference.
    pub fn new(profile_id: ProfileId, profile_digest: ProfileDigest) -> Self {
        Self {
            profile_id,
            profile_digest,
        }
    }

    /// Borrow the profile identifier.
    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }
    /// Borrow the profile digest.
    pub fn profile_digest(&self) -> &ProfileDigest {
        &self.profile_digest
    }
}

// ── BoundedProfileRefVec ──────────────────────────────────────────────────

/// A bounded vector of [`ProtocolProfileRef`] entries.
///
/// Enforces maximum length at construction time to prevent
/// resource exhaustion during bootstrap decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedProfileRefVec {
    entries: Vec<ProtocolProfileRef>,
}

impl BoundedProfileRefVec {
    /// Maximum number of profile references in a single message.
    pub const MAX_ENTRIES: usize = 64;

    /// Create an empty vector.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Access as a slice.
    pub fn as_slice(&self) -> &[ProtocolProfileRef] {
        &self.entries
    }

    /// Create from an existing vec (used during decode).
    pub fn from_vec(entries: Vec<ProtocolProfileRef>) -> Self {
        Self { entries }
    }

    /// Attempt to push an item — returns `Err(item)` if at capacity.
    pub fn push(&mut self, item: ProtocolProfileRef) -> Result<(), ProtocolProfileRef> {
        if self.entries.len() >= Self::MAX_ENTRIES {
            return Err(item);
        }
        self.entries.push(item);
        Ok(())
    }
}

// ── ProtocolSupportProfile ────────────────────────────────────────────────

/// Exact tuple per ADR-0015 — all components bound together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSupportProfile {
    /// Profile identifier.
    pub profile_id: ProfileId,
    /// Protocol version this profile targets.
    pub version: ProtocolVersion,
    /// Digest of the bootstrap message schema.
    pub bootstrap_schema_digest: BootstrapSchemaDigest,
    /// Digest of the wire contract specification.
    pub wire_contract_digest: WireContractDigest,
    /// Digest of the session schema bundle.
    pub session_schema_bundle_digest: SchemaBundleDigest,
    /// Digest of the bounds profile definition.
    pub bounds_profile_digest: BoundsProfileDigest,
}

// ── DirectionBounds / BoundsProfile ────────────────────────────────────────

/// Per-direction flow control bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectionBounds {
    /// Initial data frame credit for this direction.
    pub initial_data_frame_credit: u32,
    /// Initial encoded byte credit for this direction.
    pub initial_encoded_byte_credit: u64,
    /// Maximum data frame window size.
    pub max_data_frame_window: u32,
    /// Maximum encoded byte window size.
    pub max_encoded_byte_window: u64,
    /// Maximum in-flight requests in this direction.
    pub max_in_flight_requests: u32,
}

/// Combined flow control and protocol bounds for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundsProfile {
    /// Host-to-plugin flow control bounds.
    pub host_to_plugin: DirectionBounds,
    /// Plugin-to-host flow control bounds.
    pub plugin_to_host: DirectionBounds,
    /// Maximum control frame bytes.
    pub max_control_frame_bytes: u32,
    /// Maximum queued control frames.
    pub max_queued_control_frames: u32,
}

// ── ProtocolValidationError ───────────────────────────────────────────────

/// Session and negotiation validation errors — separate from wire-level DecodeError.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolValidationError {
    /// Profile was not in the supported set.
    ProfileNotSupported,
    /// Protocol versions are incompatible.
    ProtocolVersionMismatch {
        expected: ProtocolVersion,
        actual: ProtocolVersion,
    },
    /// Sequence number gap detected.
    SequenceGap { expected: u64, actual: u64 },
    /// Session ID mismatch.
    SessionMismatch,
    /// Profile ID or digest mismatch.
    ProfileMismatch,
    /// Payload digest does not match actual payload.
    PayloadDigestMismatch,
    /// Message digest does not match.
    MessageDigestMismatch,
    /// Correlation ID mismatch.
    CorrelationMismatch,
    /// Host or plugin identity mismatch.
    IdentityMismatch,
    /// Deadline is in the past or otherwise invalid.
    DeadlineInvalid,
}

impl std::fmt::Display for ProtocolValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProfileNotSupported => write!(f, "profile not supported"),
            Self::ProtocolVersionMismatch { expected, actual } => {
                write!(
                    f,
                    "protocol version mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::SequenceGap { expected, actual } => {
                write!(f, "sequence gap: expected {}, got {}", expected, actual)
            }
            Self::SessionMismatch => write!(f, "session ID mismatch"),
            Self::ProfileMismatch => write!(f, "profile mismatch"),
            Self::PayloadDigestMismatch => write!(f, "payload digest mismatch"),
            Self::MessageDigestMismatch => write!(f, "message digest mismatch"),
            Self::CorrelationMismatch => write!(f, "correlation mismatch"),
            Self::IdentityMismatch => write!(f, "identity mismatch"),
            Self::DeadlineInvalid => write!(f, "deadline is invalid"),
        }
    }
}

impl std::error::Error for ProtocolValidationError {}

// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_ref_vec_bounded() {
        let mut v = BoundedProfileRefVec::new();
        let pid = ProfileId::new("p1").unwrap();
        let pd = ProfileDigest::from_bytes([0; 32]);
        assert!(v.push(ProtocolProfileRef::new(pid, pd)).is_ok());
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_decode_limits_default() {
        let limits = DecodeLimits::default();
        assert_eq!(limits.max_frame_bytes, 1024 * 1024);
    }

    #[test]
    fn test_validation_error_display() {
        let err = ProtocolValidationError::SequenceGap {
            expected: 5,
            actual: 7,
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("7"));
    }

    #[test]
    fn test_protocol_support_profile_fields() {
        let p = ProtocolSupportProfile {
            profile_id: ProfileId::new("test").unwrap(),
            version: ProtocolVersion::V1_0,
            bootstrap_schema_digest: BootstrapSchemaDigest::from_bytes([1; 32]),
            wire_contract_digest: WireContractDigest::from_bytes([2; 32]),
            session_schema_bundle_digest: SchemaBundleDigest::from_bytes([3; 32]),
            bounds_profile_digest: BoundsProfileDigest::from_bytes([4; 32]),
        };
        assert_eq!(p.version, ProtocolVersion::V1_0);
        assert_eq!(p.profile_id.as_str(), "test");
    }

    #[test]
    fn test_direction_bounds_clone() {
        let d = DirectionBounds {
            initial_data_frame_credit: 10,
            initial_encoded_byte_credit: 1000,
            max_data_frame_window: 64,
            max_encoded_byte_window: 65536,
            max_in_flight_requests: 8,
        };
        let d2 = d;
        assert_eq!(d2.max_in_flight_requests, 8);
    }

    #[test]
    fn test_validation_error_is_error_trait() {
        let e: &dyn std::error::Error = &ProtocolValidationError::ProfileNotSupported;
        assert_eq!(e.to_string(), "profile not supported");
    }
}
