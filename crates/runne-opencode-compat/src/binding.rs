//! Durable session-to-conversation binding contracts.

use runne_api::{
    ApiActor, ApiPrincipalId, NonNegativeUnixMillis, OpenCodeSessionInfo, ResponseSeed,
};
use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};

use crate::profile::ProfileId;

/// Maximum UTF-8 byte length accepted for compatibility identity strings.
pub const MAX_BINDING_IDENTITY_BYTES: usize = 256;
/// Maximum entries returned by a single recovery listing request.
pub const MAX_RECOVERY_PENDING_LIMIT: usize = 1_000;

/// Reason a compatibility identity string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingIdentityError {
    /// The identifier is empty.
    Empty,
    /// The identifier exceeds the bounded wire/storage representation.
    TooLong { max: usize, actual: usize },
    /// The identifier contains NUL, C0, or DEL.
    InvalidChar { position: usize, byte: u8 },
}

/// OpenCode-owned session identifier. It is intentionally not a runtime UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpenCodeSessionId(String);

impl OpenCodeSessionId {
    /// Validates a baseline session identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, BindingIdentityError> {
        Ok(Self(validate_identity(value.into())?))
    }

    /// Returns the validated baseline session identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Runtime authority responsible for a set of session bindings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindingRuntimeAuthorityId(String);

impl BindingRuntimeAuthorityId {
    /// Validates a runtime authority identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, BindingIdentityError> {
        Ok(Self(validate_identity(value.into())?))
    }

    /// Returns the validated runtime authority identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_identity(value: String) -> Result<String, BindingIdentityError> {
    if value.is_empty() {
        return Err(BindingIdentityError::Empty);
    }
    if value.len() > MAX_BINDING_IDENTITY_BYTES {
        return Err(BindingIdentityError::TooLong {
            max: MAX_BINDING_IDENTITY_BYTES,
            actual: value.len(),
        });
    }
    if let Some((position, byte)) = value
        .bytes()
        .enumerate()
        .find(|(_, byte)| *byte == 0 || *byte < 0x20 || *byte == 0x7f)
    {
        return Err(BindingIdentityError::InvalidChar { position, byte });
    }
    Ok(value)
}

/// Immutable identity of a session binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionBindingKey {
    /// Baseline session ID, never a runtime conversation ID.
    pub session_id: OpenCodeSessionId,
    /// Compatibility profile identifier.
    pub profile_id: ProfileId,
    /// Compatibility profile revision.
    pub profile_revision: u16,
    /// Runtime authority that owns the binding.
    pub runtime_authority_id: BindingRuntimeAuthorityId,
}

/// SHA-256 fingerprint of the semantic baseline create payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreateFingerprint([u8; 32]);

impl SessionCreateFingerprint {
    /// Creates a fingerprint from its SHA-256 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the SHA-256 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical context bound to the baseline session before the host is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBindingContext {
    /// Runtime-owned conversation identifier.
    pub conversation_id: ConversationId,
    /// Runtime-owned workspace identifier.
    pub workspace_id: WorkspaceId,
    /// Runtime-owned command identifier.
    pub command_id: CommandId,
    /// Caller-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Fingerprint of the baseline wire payload.
    pub request_fingerprint: SessionCreateFingerprint,
    /// Supported baseline title.
    pub title: Option<String>,
    /// Authenticated principal.
    pub principal: ApiPrincipalId,
    /// Command actor.
    pub actor: ApiActor,
    /// Stable response reconstruction values.
    pub response_seed: ResponseSeed,
}

/// Durable state of a session binding.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionBindingStatus {
    /// Host work may be retried using this exact context.
    Pending { context: SessionBindingContext },
    /// Host work completed and the exact wire response is durable.
    Committed {
        context: SessionBindingContext,
        response: OpenCodeSessionInfo,
    },
}

/// Outcome of attempting to create the pending binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsurePendingResult {
    /// A new pending binding was written.
    Created,
    /// A matching or conflicting pending binding already exists.
    AlreadyPending,
    /// A matching or conflicting committed binding already exists.
    AlreadyCommitted,
}

/// Failure returned by a durable binding adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// A compare-and-swap or uniqueness condition failed.
    Conflict(SessionBindingKey),
    /// The requested binding did not exist.
    NotFound(SessionBindingKey),
    /// Durable storage was unavailable or failed.
    StorageFailure,
    /// Durable serialization or decoding failed.
    SerializationFailed,
    /// The recovery page bound was outside the shared contract.
    InvalidLimit { max: usize, actual: usize },
}

/// Durability port for session bindings.
pub trait SessionBindingStore {
    /// Ensures the exact context has a durable pending binding.
    fn ensure_pending(
        &self,
        key: &SessionBindingKey,
        context: &SessionBindingContext,
    ) -> Result<EnsurePendingResult, BindingError>;

    /// Commits a pending binding using compare-and-swap semantics.
    fn commit(
        &self,
        key: &SessionBindingKey,
        expected_conversation_id: ConversationId,
        response: &OpenCodeSessionInfo,
    ) -> Result<(), BindingError>;

    /// Looks up the full binding state for exact context comparison.
    fn lookup(&self, key: &SessionBindingKey)
    -> Result<Option<SessionBindingStatus>, BindingError>;

    /// Lists pending bindings for a single authority using a keyset cursor.
    fn list_pending(
        &self,
        authority: &BindingRuntimeAuthorityId,
        limit: usize,
        after: Option<&(NonNegativeUnixMillis, SessionBindingKey)>,
    ) -> Result<Vec<(NonNegativeUnixMillis, SessionBindingKey)>, BindingError>;
}
