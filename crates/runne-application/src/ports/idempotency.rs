// ── Idempotency scope ──────────────────────────────────────────────────────

/// Identifies the runtime authority (the Runne host process).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeAuthorityId(pub String);

/// Identifies the principal (user/service) that issued a command.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrincipalId(pub String);

/// Operation tag — a numeric discriminant for each use case.
///
/// Used in idempotency scope and CommandFingerprint canonical encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperationTag {
    /// Create a new task run.
    CreateTaskRun = 1,
    /// Queue a task run for admission.
    Queue = 2,
    /// Admit a task run for execution.
    Admit = 3,
    /// Start a new execution attempt.
    StartAttempt = 4,
    /// Complete a task run with a terminal result.
    Complete = 5,
    /// Create a new conversation.
    CreateConversation = 6,
    StartLoopCycle = 7,
    CommitContext = 8,
    CommitPlan = 9,
    RecordStepOutcome = 10,
    CompleteLoopCycle = 11,
    CreateNextCycle = 12,
    ScheduleRetry = 13,
    ActivateScheduledRetryAttempt = 14,
    CommitRecoveryResume = 15,
    CommitLoopCheckpoint = 16,
    ResumeLoopWait = 17,
    /// Append a user message and execute deterministic local text generation.
    GenerateConversationText = 18,
    /// Request cancellation of an existing task run.
    CancelTaskRun = 19,
    /// Client-authorized atomic TaskRun submit (created + queued in one commit).
    SubmitTaskRun = 20,
    /// Runtime-owned atomic node assignment and attempt start.
    TaskRunClaim = 21,
}

/// The aggregate scope within which idempotency is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AggregateScope {
    /// A task run that does not yet exist (for Create).
    NewTaskRun {
        /// The conversation this task run belongs to.
        conversation_id: ConversationId,
        /// The workspace this task run belongs to.
        workspace_id: WorkspaceId,
    },
    /// An existing task run.
    ExistingTaskRun {
        /// The task run ID.
        taskrun_id: TaskRunId,
    },
    /// A conversation that does not yet exist.
    NewConversation {
        /// Conversation identity selected by the API boundary.
        conversation_id: ConversationId,
        /// Workspace that owns the conversation.
        workspace_id: WorkspaceId,
    },
    /// An existing Conversation.
    ExistingConversation {
        /// Target Conversation.
        conversation_id: ConversationId,
    },
}

/// Full idempotency scope — runtime, principal, operation, and aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyScope {
    /// The runtime authority that processed the command.
    pub runtime_authority_id: RuntimeAuthorityId,
    /// The principal that issued the command.
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// The operation being performed.
    pub operation: OperationTag,
    /// The aggregate scope (new or existing task run).
    pub aggregate_scope: AggregateScope,
}

/// Application command context — identity and metadata carried by every command.
#[derive(Debug, Clone)]
pub struct ApplicationCommandContext {
    /// Unique command identifier.
    pub command_id: runne_domain::id::CommandId,
    /// Client-supplied idempotency key.
    pub idempotency_key: runne_domain::id::IdempotencyKey,
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// Domain actor for event attribution.
    pub actor: runne_domain::event::Actor,
}
