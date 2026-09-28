/// Validated request for creating a Conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateConversationRequest {
    identity: CommandIdentity,
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    scope: ConversationContextScope,
}

impl CreateConversationRequest {
    /// Creates a typed create request. The delivery-context scope is part of
    /// the durable conversation identity and must be stated explicitly.
    #[must_use]
    pub const fn new(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        scope: ConversationContextScope,
    ) -> Self {
        Self {
            identity,
            conversation_id,
            workspace_id,
            scope,
        }
    }

    /// Durable delivery context carried by this request.
    #[must_use]
    pub const fn scope(&self) -> ConversationContextScope {
        self.scope
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

/// Validated request for the runtime-owned atomic `TaskRun` submit.
#[derive(Clone, Eq, PartialEq)]
pub struct SubmitTaskRunRequest {
    pub(crate) identity: CommandIdentity,
    pub(crate) conversation_id: CanonicalId,
    pub(crate) workspace_id: CanonicalId,
    pub(crate) prompt: String,
    pub(crate) model: Option<String>,
}

impl std::fmt::Debug for SubmitTaskRunRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubmitTaskRunRequest")
            .field("identity", &self.identity)
            .field("conversation_id", &self.conversation_id)
            .field("workspace_id", &self.workspace_id)
            .field("prompt", &"[REDACTED]")
            .field("model", &self.model)
            .finish()
    }
}

impl SubmitTaskRunRequest {
    /// Creates a typed submit request. The runtime owns the new `TaskRun`
    /// identity; the caller supplies only the referenced aggregate roots.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the prompt is invalid.
    pub fn new(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let prompt = prompt.into();
        runne_api::TaskRunInput::new(prompt.clone())
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        Ok(Self {
            identity,
            conversation_id,
            workspace_id,
            prompt,
            model: None,
        })
    }

    /// Requests the exact provider model. Admission compares it against the
    /// runtime-pinned model; a mismatch is rejected before any effect.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

/// IDs-only compatibility request for the v1 `TaskRun` submit operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitTaskRunV1Request {
    pub(crate) identity: CommandIdentity,
    pub(crate) conversation_id: CanonicalId,
    pub(crate) workspace_id: CanonicalId,
}

impl SubmitTaskRunV1Request {
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
