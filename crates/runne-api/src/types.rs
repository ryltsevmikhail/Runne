//! API data transfer objects and timestamp newtypes.

use runne_domain::id::{CommandId, ConversationId, IdempotencyKey, WorkspaceId};

/// Unix millisecond timestamp, including timestamps before the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixMillis(i64);

impl UnixMillis {
    /// Creates a timestamp from signed Unix milliseconds.
    pub const fn new(ms: i64) -> Self {
        Self(ms)
    }

    /// Returns the signed Unix milliseconds.
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

/// Unix millisecond timestamp that cannot precede the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonNegativeUnixMillis(i64);

impl NonNegativeUnixMillis {
    /// Creates a timestamp when `ms` is non-negative.
    pub const fn new(ms: i64) -> Option<Self> {
        if ms >= 0 { Some(Self(ms)) } else { None }
    }

    /// Returns the non-negative Unix milliseconds.
    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

/// Input for creating a conversation through the runtime host port.
#[derive(Debug, Clone)]
pub struct CreateConversationInput {
    /// Conversation aggregate identifier to create.
    pub conversation_id: ConversationId,
    /// Workspace that owns the conversation.
    pub workspace_id: WorkspaceId,
    /// Command identifier for deduplication and tracing.
    pub command_id: CommandId,
    /// Client supplied idempotency key.
    pub idempotency_key: IdempotencyKey,
}

/// Result returned after a conversation has been created durably.
#[derive(Debug, Clone)]
pub struct CreateConversationOutput {
    /// Created conversation aggregate identifier.
    pub conversation_id: ConversationId,
    /// Workspace that owns the created conversation.
    pub workspace_id: WorkspaceId,
    /// Time at which the operation committed.
    pub committed_at: NonNegativeUnixMillis,
    /// Committed conversation stream version.
    pub stream_version: u64,
}

/// Byte-stable values used to reconstruct OpenCode `Session.Info` responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSeed {
    /// OpenCode project identifier.
    pub project_id: String,
    /// OpenCode session directory.
    pub directory: String,
    /// Optional OpenCode session path.
    pub path: Option<String>,
    /// OpenCode version string.
    pub version: String,
    /// Optional OpenCode workspace identifier.
    pub workspace_id: Option<String>,
}

/// Closed set of failures returned by a runtime host port.
#[derive(Debug, Clone)]
pub enum HostError {
    /// A different conversation already occupies the requested identifier.
    ConversationAlreadyExists(ConversationId),
    /// The host could not persist required state.
    StorageFailure,
    /// The host did not complete before its deadline.
    Timeout,
}
