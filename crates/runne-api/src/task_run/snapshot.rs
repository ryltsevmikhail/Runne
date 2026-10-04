use super::CanonicalTerminalResult;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId, WorkspaceId};

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
    /// Conversation bound at creation, when the run carries one.
    pub conversation_id: Option<ConversationId>,
    /// Workspace bound at creation, when the run carries one.
    pub workspace_id: Option<WorkspaceId>,
    /// Reconstructed lifecycle state.
    pub state: CanonicalTaskRunState,
    /// Current committed stream version.
    pub stream_version: u64,
    /// Active attempt, when the state has one.
    pub active_attempt_id: Option<AttemptId>,
    /// Terminal result for success/failure completion events.
    pub terminal_result: Option<CanonicalTerminalResult>,
}
