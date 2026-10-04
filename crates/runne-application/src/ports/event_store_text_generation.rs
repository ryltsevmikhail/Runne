/// Durable phase of one idempotent Conversation text execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextGenerationPhase {
    /// User message and running TaskRun are durable; provider output is pending.
    Started,
    /// Assistant message and successful terminal TaskRun are durable.
    Completed,
    /// Provider output was rejected safely without an assistant message.
    Rejected,
    /// Provider input was rejected safely before outbound delivery.
    ProhibitedInputRejected,
}

/// Durable coordination receipt linking Conversation messages to TaskRun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextGenerationReceipt {
    /// Current durable phase.
    pub phase: TextGenerationPhase,
    /// Target Conversation.
    pub conversation_id: ConversationId,
    /// Conversation workspace.
    pub workspace_id: WorkspaceId,
    /// Coordinating TaskRun.
    pub taskrun_id: TaskRunId,
    /// Exact execution attempt.
    pub attempt_id: AttemptId,
    /// Durable user message.
    pub user_message_id: MessageId,
    /// Reserved assistant message identity, stable across retries.
    pub assistant_message_id: MessageId,
    /// Current Conversation version for this phase.
    pub conversation_version: u64,
    /// Current TaskRun version for this phase.
    pub taskrun_version: u64,
}

/// Result of a text-generation receipt lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextGenerationReceiptLookup {
    /// No matching command was committed.
    Miss,
    /// The exact command has a durable started or completed phase.
    Duplicate {
        /// Original durable coordination result.
        stored_result: TextGenerationReceipt,
    },
}

/// Atomic phase-one commit for a Conversation text execution.
#[derive(Debug, Clone)]
pub struct BeginTextGenerationCommit {
    /// Unique command identity.
    pub command_id: CommandId,
    /// Client-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Full uniqueness scope.
    pub idempotency_scope: IdempotencyScope,
    /// Deterministic semantic input fingerprint.
    pub command_fingerprint: CommandFingerprint,
    /// Expected Conversation stream version.
    pub expected_conversation_version: u64,
    /// User message event to append.
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    /// TaskRun create-through-start event batch.
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    /// Started coordination receipt.
    pub receipt: TextGenerationReceipt,
}

/// Atomic phase-two commit for a Conversation text execution.
#[derive(Debug, Clone)]
pub struct FinishTextGenerationCommit {
    /// Original command identity.
    pub command_id: CommandId,
    /// Original client idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Original uniqueness scope.
    pub idempotency_scope: IdempotencyScope,
    /// Original semantic input fingerprint.
    pub command_fingerprint: CommandFingerprint,
    /// Expected Conversation version from the started phase.
    pub expected_conversation_version: u64,
    /// Expected TaskRun version from the started phase.
    pub expected_taskrun_version: u64,
    /// Assistant message event to append.
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    /// Successful TaskRun completion event.
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    /// Completed coordination receipt.
    pub receipt: TextGenerationReceipt,
}

/// Atomic terminal rejection for a Conversation text execution.
#[derive(Debug, Clone)]
pub struct RejectTextGenerationCommit {
    /// Original command identity.
    pub command_id: CommandId,
    /// Original client idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Original uniqueness scope.
    pub idempotency_scope: IdempotencyScope,
    /// Original semantic input fingerprint.
    pub command_fingerprint: CommandFingerprint,
    /// Expected Conversation version from the started phase.
    pub expected_conversation_version: u64,
    /// Expected TaskRun version from the started phase.
    pub expected_taskrun_version: u64,
    /// Safe generation-failure event.
    pub conversation_events: Vec<UncommittedEvent<ConversationEvent>>,
    /// Failed TaskRun terminal event.
    pub taskrun_events: Vec<UncommittedEvent<TaskRunEvent>>,
    /// Rejected coordination receipt.
    pub receipt: TextGenerationReceipt,
}

/// Result of an atomic text-generation phase commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextGenerationCommitResult {
    /// The requested phase committed.
    Committed {
        /// New durable coordination result.
        result: TextGenerationReceipt,
    },
    /// Another identical request already committed this or a later phase.
    Duplicate {
        /// Existing durable coordination result.
        stored_result: TextGenerationReceipt,
    },
}
