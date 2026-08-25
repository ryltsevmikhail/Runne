/// Validated request for creating a Conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateConversationRequest {
    identity: CommandIdentity,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
}

impl CreateConversationRequest {
    /// Creates a typed create request.
    #[must_use]
    pub const fn new(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    ) -> Self {
        Self {
            identity,
            conversation_id,
            workspace_id,
        }
    }
}

/// Validated request for one synchronous text generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateTextRequest {
    identity: CommandIdentity,
    conversation_id: CanonicalId,
    expected_version: u64,
    text: String,
}

impl GenerateTextRequest {
    /// Validates message text against the canonical byte limit.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRequest` for empty or oversized text.
    pub fn new(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        expected_version: u64,
        text: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let text = text.into();
        validate_message_text(&text)?;
        Ok(Self {
            identity,
            conversation_id,
            expected_version,
            text,
        })
    }
}

/// Validated request for asking the runtime to cancel a `TaskRun`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelTaskRunRequest {
    pub(crate) identity: CommandIdentity,
    pub(crate) task_run_id: CanonicalId,
    pub(crate) expected_version: u64,
}

impl CancelTaskRunRequest {
    /// Creates a typed cancellation request.
    #[must_use]
    pub const fn new(
        identity: CommandIdentity,
        task_run_id: CanonicalId,
        expected_version: u64,
    ) -> Self {
        Self {
            identity,
            task_run_id,
            expected_version,
        }
    }
}

/// Durable Conversation creation acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationCreated {
    pub conversation_id: CanonicalId,
    pub workspace_id: CanonicalId,
    pub stream_version: u64,
    pub committed_at: u64,
}

/// Closed canonical message role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationMessageRole {
    User,
    Assistant,
}

/// Sanitized durable Conversation message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessage {
    pub message_id: CanonicalId,
    pub role: ConversationMessageRole,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub text: String,
    pub committed_at: u64,
}

/// Completed durable text generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationTextResult {
    pub conversation_id: CanonicalId,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub conversation_stream_version: u64,
    pub task_run_stream_version: u64,
    pub user_message: ConversationMessage,
    pub assistant_message: ConversationMessage,
}

/// Authoritative ordered message snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessages {
    pub conversation_id: CanonicalId,
    pub stream_version: u64,
    pub messages: Vec<ConversationMessage>,
}
