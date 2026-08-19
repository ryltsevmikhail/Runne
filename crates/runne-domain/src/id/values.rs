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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
