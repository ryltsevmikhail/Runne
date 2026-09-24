//! Transport-neutral canonical TaskRun command and query contracts.

use runne_domain::id::{
    AttemptId, CommandId, ConversationId, IdempotencyKey, TaskRunId, WorkspaceId,
};
pub use runne_domain::task_run::{MAX_TASK_RUN_PROMPT_BYTES, TaskRunInput};

mod query_port;
pub use query_port::TaskRunQueryHostPort;

use crate::{ApiActor, ApiPrincipalId};

/// Maximum UTF-8 byte length of a canonical terminal failure reason.
pub const MAX_CANONICAL_TERMINAL_REASON_BYTES: usize = 4096;

/// Identity and idempotency context carried by every TaskRun mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunCommandContext {
    /// Unique UUIDv7 command identity.
    pub command_id: CommandId,
    /// Caller-provided key scoped by principal, operation, and aggregate.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated API principal.
    pub principal: ApiPrincipalId,
    /// Client or adapter actor recorded in committed events.
    pub actor: ApiActor,
}

/// Canonical input for creating one TaskRun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateTaskRunCommand {
    /// Conversation referenced by the new TaskRun.
    pub conversation_id: ConversationId,
    /// Workspace referenced by the new TaskRun.
    pub workspace_id: WorkspaceId,
}

/// Canonical input for the atomic client-authorized TaskRun submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitTaskRunCommand {
    /// Conversation referenced by the new TaskRun.
    pub conversation_id: ConversationId,
    /// Workspace referenced by the new TaskRun.
    pub workspace_id: WorkspaceId,
    /// Exact, validated prompt submitted by the caller.
    pub input: TaskRunInput,
}

/// Historical promptless atomic submit retained at the v1 wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacySubmitTaskRunCommand {
    pub conversation_id: ConversationId,
    pub workspace_id: WorkspaceId,
}

/// Canonical input for a transition on an existing TaskRun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingTaskRunCommand {
    /// Target TaskRun.
    pub taskrun_id: TaskRunId,
    /// Stream version the caller expects before the transition.
    pub expected_version: u64,
}

/// Closed terminal result exposed by the canonical API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalTerminalResult {
    /// The TaskRun completed successfully.
    Success,
    /// The TaskRun failed with a bounded, caller-visible reason.
    Failure {
        /// Failure reason.
        reason: String,
    },
}

/// Canonical input for completing a running TaskRun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteTaskRunCommand {
    /// Target TaskRun.
    pub taskrun_id: TaskRunId,
    /// Stream version the caller expects before completion.
    pub expected_version: u64,
    /// Exact terminal disposition.
    pub result: CanonicalTerminalResult,
}

/// Exact committed transition acknowledged by a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunCommandAckKind {
    /// A TaskRun was created.
    Created,
    /// One atomic submit committed `Created + Queued` as a single unit.
    Submitted,
    /// A TaskRun entered the queue.
    Queued,
    /// Cancellation was durably requested.
    CancellationRequested,
    /// A TaskRun was admitted.
    Admitted,
    /// A new execution attempt started.
    AttemptStarted {
        /// Committed attempt identity.
        attempt_id: AttemptId,
    },
    /// A TaskRun reached its terminal result.
    Completed {
        /// Committed terminal result.
        result: CanonicalTerminalResult,
    },
}

/// Durable acknowledgement returned by a canonical mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunCommandAck {
    /// Mutated TaskRun.
    pub taskrun_id: TaskRunId,
    /// Resulting committed stream version.
    pub new_version: u64,
    /// Exact transition that committed.
    pub kind: TaskRunCommandAckKind,
}

/// Closed TaskRun lifecycle representation for canonical clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalTaskRunState {
    /// Created but not queued.
    Created,
    /// Waiting for admission.
    Queued,
    /// Admitted but not executing.
    Admitted,
    /// One attempt is active.
    Running,
    /// Waiting for approval or input.
    Waiting,
    /// Waiting for or executing a retry.
    Retrying,
    /// A checkpoint is being committed.
    Checkpointing,
    /// Cancellation is in progress.
    Cancelling,
    /// Effect reconciliation is in progress.
    Reconciling,
    /// Successful terminal state.
    Succeeded,
    /// Failed terminal state.
    Failed,
    /// Cancelled terminal state.
    Cancelled,
    /// Budget-exhausted terminal state.
    BudgetExhausted,
    /// Policy-denied terminal state.
    PolicyDenied,
    /// Unrecoverable terminal state.
    Unrecoverable,
}

impl CanonicalTaskRunState {
    /// Returns the stable wire spelling used by transport adapters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Queued => "queued",
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::Retrying => "retrying",
            Self::Checkpointing => "checkpointing",
            Self::Cancelling => "cancelling",
            Self::Reconciling => "reconciling",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::BudgetExhausted => "budget_exhausted",
            Self::PolicyDenied => "policy_denied",
            Self::Unrecoverable => "unrecoverable",
        }
    }
}

/// Non-mutating snapshot reconstructed from a committed TaskRun stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRunSnapshot {
    /// Queried TaskRun.
    pub taskrun_id: TaskRunId,
    /// Reconstructed lifecycle state.
    pub state: CanonicalTaskRunState,
    /// Current committed stream version.
    pub stream_version: u64,
    /// Active attempt, when the state has one.
    pub active_attempt_id: Option<AttemptId>,
    /// Terminal result for success/failure completion events.
    pub terminal_result: Option<CanonicalTerminalResult>,
}

/// Closed redacted failures returned by canonical TaskRun hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunHostError {
    /// The requested TaskRun does not exist.
    NotFound,
    /// Expected version, state, command identity, or idempotency conflicted.
    Conflict,
    /// A bounded runtime queue rejected the request.
    Backpressure,
    /// Runtime or persistence is unavailable.
    Unavailable,
    /// A host outcome violated the canonical API contract.
    InvariantViolation,
}

impl TaskRunHostError {
    /// Stable code suitable for a redacted transport error envelope.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "task_run_not_found",
            Self::Conflict => "task_run_conflict",
            Self::Backpressure => "runtime_backpressure",
            Self::Unavailable => "runtime_unavailable",
            Self::InvariantViolation => "runtime_invariant_violation",
        }
    }
}

/// Runtime host boundary for canonical TaskRun mutations.
pub trait TaskRunCommandHostPort: Send + Sync {
    /// Creates one TaskRun and durably commits its initial event.
    fn create_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CreateTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send;

    /// Submits one TaskRun as one atomic `Created + Queued` unit-of-work.
    ///
    /// Never implemented as a `create` then `queue` sequence. Hosts that do
    /// not yet authorize the bounded submit command fail closed as
    /// unavailable until the capability contract is published.
    fn submit_task_run(
        &self,
        _context: TaskRunCommandContext,
        _command: SubmitTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send {
        async { Err(TaskRunHostError::Unavailable) }
    }

    /// Executes the published v1 promptless submit contract.
    fn submit_task_run_legacy(
        &self,
        _context: TaskRunCommandContext,
        _command: LegacySubmitTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send {
        async { Err(TaskRunHostError::Unavailable) }
    }

    /// Queues one created TaskRun.
    fn queue_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send;

    /// Requests cancellation through the authoritative TaskRun aggregate.
    fn request_task_run_cancellation(
        &self,
        _context: TaskRunCommandContext,
        _command: ExistingTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send {
        async { Err(TaskRunHostError::Unavailable) }
    }

    /// Admits one queued TaskRun.
    fn admit_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send;

    /// Starts a new attempt for one admitted TaskRun.
    fn start_attempt(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send;

    /// Completes one running TaskRun.
    fn complete_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CompleteTaskRunCommand,
    ) -> impl std::future::Future<Output = Result<TaskRunCommandAck, TaskRunHostError>> + Send;
}
