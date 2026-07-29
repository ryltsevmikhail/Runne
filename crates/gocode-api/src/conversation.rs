//! Transport-neutral canonical Conversation command and query contracts.

use gocode_domain::id::{
    AttemptId, CommandId, ConversationId, IdempotencyKey, MessageId, TaskRunId, WorkspaceId,
};
use gocode_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};

use crate::{ApiActor, ApiPrincipalId, NonNegativeUnixMillis};

/// Identity and idempotency context carried by Conversation mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationCommandContext {
    /// Unique UUIDv7 command identity.
    pub command_id: CommandId,
    /// Caller-provided key scoped by principal, operation, and Conversation.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated API principal.
    pub principal: ApiPrincipalId,
    /// Client or adapter actor recorded in committed events.
    pub actor: ApiActor,
}

/// Canonical input for creating a Conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateCanonicalConversationCommand {
    /// Client-selected Conversation identity.
    pub conversation_id: ConversationId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
}

/// Durable acknowledgement of Conversation creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationCreatedAck {
    /// Created Conversation.
    pub conversation_id: ConversationId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Resulting stream version.
    pub stream_version: u64,
    /// Persistence-authoritative commit time.
    pub committed_at: NonNegativeUnixMillis,
}

/// Validated canonical text accepted by the API boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalMessageText(MessageText);

impl CanonicalMessageText {
    /// Validates non-empty UTF-8 text against the canonical byte bound.
    pub fn new(value: impl Into<String>) -> Result<Self, CanonicalMessageTextError> {
        MessageText::new(value)
            .map(Self)
            .map_err(|error| match error {
                gocode_domain::message::MessageTextError::Empty => CanonicalMessageTextError::Empty,
                gocode_domain::message::MessageTextError::TooLarge { max, actual } => {
                    CanonicalMessageTextError::TooLarge { max, actual }
                }
            })
    }

    /// Returns the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Converts into the domain value at the application boundary.
    #[must_use]
    pub fn into_domain(self) -> MessageText {
        self.0
    }
}

/// Closed validation failures for canonical message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalMessageTextError {
    /// Empty text is invalid.
    Empty,
    /// UTF-8 bytes exceeded the canonical limit.
    TooLarge {
        /// Maximum accepted byte length.
        max: usize,
        /// Actual byte length.
        actual: usize,
    },
}

/// Canonical synchronous local text-generation command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateConversationTextCommand {
    /// Target Conversation.
    pub conversation_id: ConversationId,
    /// Stream version expected before appending the user message.
    pub expected_version: u64,
    /// Validated user message text.
    pub text: CanonicalMessageText,
}

/// Closed role set exposed to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalMessageRole {
    /// Caller-authored message.
    User,
    /// Runtime-generated message.
    Assistant,
}

impl CanonicalMessageRole {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

/// One durable text message in a Conversation timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalConversationMessage {
    /// Message identity.
    pub message_id: MessageId,
    /// User or assistant role.
    pub role: CanonicalMessageRole,
    /// Coordinating TaskRun.
    pub taskrun_id: TaskRunId,
    /// Exact execution attempt.
    pub attempt_id: AttemptId,
    /// Message text.
    pub text: String,
    /// Persistence-authoritative event time.
    pub committed_at: NonNegativeUnixMillis,
}

/// Completed deterministic text execution returned to a canonical client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationTextResult {
    /// Target Conversation.
    pub conversation_id: ConversationId,
    /// Coordinating TaskRun.
    pub taskrun_id: TaskRunId,
    /// Exact execution attempt.
    pub attempt_id: AttemptId,
    /// Conversation stream version after assistant output.
    pub conversation_stream_version: u64,
    /// Terminal TaskRun stream version.
    pub taskrun_stream_version: u64,
    /// Durable user message.
    pub user_message: CanonicalConversationMessage,
    /// Durable assistant message.
    pub assistant_message: CanonicalConversationMessage,
}

/// Non-mutating Conversation message timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMessagesSnapshot {
    /// Queried Conversation.
    pub conversation_id: ConversationId,
    /// Current committed stream version.
    pub stream_version: u64,
    /// Ordered durable messages.
    pub messages: Vec<CanonicalConversationMessage>,
}

/// Closed redacted failures returned by canonical Conversation hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationHostError {
    /// The Conversation does not exist.
    NotFound,
    /// Version, lifecycle, command identity, or idempotency conflicted.
    Conflict,
    /// A bounded runtime queue rejected the request.
    Backpressure,
    /// Runtime or persistence is unavailable.
    Unavailable,
    /// A host outcome violated the canonical contract.
    InvariantViolation,
}

impl ConversationHostError {
    /// Stable redacted transport error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "conversation_not_found",
            Self::Conflict => "conversation_conflict",
            Self::Backpressure => "runtime_backpressure",
            Self::Unavailable => "runtime_unavailable",
            Self::InvariantViolation => "runtime_invariant_violation",
        }
    }
}

/// Runtime host boundary for canonical Conversation mutations.
pub trait ConversationCommandHostPort: Send + Sync {
    /// Creates one Conversation and durably commits its initial event.
    fn create_conversation(
        &self,
        context: ConversationCommandContext,
        command: CreateCanonicalConversationCommand,
    ) -> impl std::future::Future<Output = Result<ConversationCreatedAck, ConversationHostError>> + Send;

    /// Appends user text, executes the local provider, and commits assistant text.
    fn generate_text(
        &self,
        context: ConversationCommandContext,
        command: GenerateConversationTextCommand,
    ) -> impl std::future::Future<Output = Result<ConversationTextResult, ConversationHostError>> + Send;
}

/// Runtime host boundary for canonical Conversation queries.
pub trait ConversationQueryHostPort: Send + Sync {
    /// Reconstructs the ordered message timeline from committed events.
    fn list_messages(
        &self,
        conversation_id: ConversationId,
    ) -> impl std::future::Future<
        Output = Result<ConversationMessagesSnapshot, ConversationHostError>,
    > + Send;
}

/// Returns the canonical message byte bound for transport adapters.
#[must_use]
pub const fn max_message_text_bytes() -> usize {
    MAX_MESSAGE_TEXT_BYTES
}
