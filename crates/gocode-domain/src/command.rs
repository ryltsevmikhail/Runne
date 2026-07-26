//! Domain commands — what the application layer sends to aggregates.
//!
//! Commands are pure data; the domain decides whether to accept them
//! and produce events.

use crate::id::{AttemptId, ConversationId, TaskRunId, WorkspaceId};

// ── TerminalResult ─────────────────────────────────────────────────────────

/// The outcome of a completed task run (succeeded or failed).
///
/// Other terminal states (cancelled, budget_exhausted, policy_denied,
/// unrecoverable) have their own dedicated events and do not carry
/// a `TerminalResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalResult {
    /// The task completed successfully.
    Success,
    /// The task failed with a reason.
    /// The reason the task failed.
    Failure { reason: String },
}

// ── CreateTaskRun ──────────────────────────────────────────────────────────

/// Command to create a new [`TaskRun`](crate::task_run::TaskRun) aggregate.
///
/// Carries the aggregate identity and parent conversation / workspace
/// references.
#[derive(Debug, Clone)]
pub struct CreateTaskRun {
    /// The ID to assign to the new task run.
    pub taskrun_id: TaskRunId,
    /// The conversation this task run belongs to.
    pub conversation_id: ConversationId,
    /// The workspace this task run belongs to.
    pub workspace_id: WorkspaceId,
}

// ── TaskRunCommand ────────────────────────────────────────────────────────

/// All commands that can be sent to an existing [`TaskRun`](crate::task_run::TaskRun) aggregate.
#[derive(Debug, Clone)]
pub enum TaskRunCommand {
    /// Admit the task run for execution.
    Admit,

    /// Start a new attempt.
    StartAttempt {
        /// The ID to assign to the new attempt.
        attempt_id: AttemptId,
    },

    /// Wait for approval or external input.
    WaitForApproval,

    /// Resume execution after waiting.
    Resume,

    /// Start a retry.
    StartRetry {
        /// The ID to assign to the retry attempt.
        attempt_id: AttemptId,
    },

    /// Complete a retry.
    CompleteRetry {
        /// The ID of the attempt that completed retry.
        attempt_id: AttemptId,
    },

    /// Begin a checkpoint operation.
    StartCheckpoint,

    /// Commit a checkpoint — transitions back to running.
    CommitCheckpoint,

    /// Request cancellation of the task run.
    RequestCancellation,

    /// Complete cancellation — transitions to the terminal cancelled state.
    CompleteCancellation,

    /// Complete execution with a result.
    Complete {
        /// The terminal result (success or failure).
        result: TerminalResult,
    },

    /// Mark the task run as failed.
    Fail {
        /// The reason the task failed.
        reason: String,
    },

    /// Start a reconciliation pass.
    StartReconciliation,

    /// Complete a reconciliation pass — transitions back to running.
    CompleteReconciliation,

    /// Mark the task run as unrecoverable (terminal).
    MarkUnrecoverable,
}
