/// Atomic persistence boundary for conversation streams and create receipts.
pub trait ConversationRepository {
    /// Loads a committed conversation stream.
    fn load_conversation(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationLoadedStream, EventStoreError>;

    /// Looks up the durable result of a create-conversation command.
    /// A duplicate requires the exact command ID, scope, idempotency key, and
    /// semantic fingerprint; changing any field is a conflict.
    fn lookup_conversation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<ConversationReceiptLookup, CommitError>;

    /// Atomically rechecks the full command identity, appends conversation
    /// events, and stores their create receipt.
    fn commit_conversation(
        &self,
        payload: ConversationCommit,
    ) -> Result<ConversationCommitResult, CommitError>;
}

/// Atomic persistence boundary for coordinated Conversation text execution.
pub trait ConversationTextRepository {
    /// Looks up the durable phase of an idempotent text-generation command.
    fn lookup_text_generation_receipt(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        idempotency_scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<TextGenerationReceiptLookup, CommitError>;

    /// Atomically appends the user message, starts its TaskRun, and stores a
    /// `Started` receipt before provider execution.
    fn begin_text_generation(
        &self,
        payload: BeginTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError>;

    /// Atomically appends assistant output, completes its TaskRun, and advances
    /// the original receipt to `Completed`.
    fn finish_text_generation(
        &self,
        payload: FinishTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError>;

    /// Atomically releases the generation, fails its TaskRun, and advances the
    /// original receipt to `Rejected` without an assistant message.
    fn reject_text_generation(
        &self,
        payload: RejectTextGenerationCommit,
    ) -> Result<TextGenerationCommitResult, CommitError>;
}

/// A committed conversation stream.
#[derive(Debug, Clone)]
pub struct ConversationLoadedStream {
    /// Events ordered by their contiguous stream sequence.
    pub events: Vec<EventEnvelope<ConversationEvent>>,
    /// Last committed stream sequence, or zero for an empty stream.
    pub current_version: u64,
    /// Last committed event identity, if any.
    pub last_event_id: Option<EventId>,
}

/// Durable result of a create-conversation command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationReceipt {
    /// Conversation created by the command.
    pub conversation_id: ConversationId,
    /// Workspace recorded by the creation event.
    pub workspace_id: WorkspaceId,
    /// Resulting stream version.
    pub new_version: u64,
    /// Persistence-authoritative commit timestamp.
    pub committed_at: Timestamp,
}

/// Result of a conversation receipt lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationReceiptLookup {
    /// No matching receipt exists.
    Miss,
    /// The exact command was committed previously.
    Duplicate {
        /// Original durable result.
        stored_result: ConversationReceipt,
    },
}

/// Atomic conversation event and receipt commit payload.
#[derive(Debug, Clone)]
pub struct ConversationCommit {
    /// Unique command identity.
    pub command_id: CommandId,
    /// Client-provided idempotency key.
    pub idempotency_key: IdempotencyKey,
    /// Full uniqueness scope for the key.
    pub idempotency_scope: IdempotencyScope,
    /// Deterministic semantic command fingerprint.
    pub command_fingerprint: CommandFingerprint,
    /// Expected conversation stream version.
    pub expected_version: u64,
    /// Conversation events to append.
    pub events: Vec<UncommittedEvent<ConversationEvent>>,
    /// Workspace expected in the creation event and receipt.
    pub workspace_id: WorkspaceId,
    /// Durable delivery-context marker recorded with the creation event.
    pub context_scope: runne_domain::conversation::ConversationContextScope,
}

/// Result of an atomic conversation commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationCommitResult {
    /// Events and receipt were committed.
    Committed {
        /// Durable create result.
        result: ConversationReceipt,
    },
    /// The exact command was committed previously.
    Duplicate {
        /// Original durable create result.
        stored_result: ConversationReceipt,
    },
}

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
