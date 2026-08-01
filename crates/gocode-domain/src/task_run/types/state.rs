use super::*;

// ── TaskRunState ───────────────────────────────────────────────────────────

/// All possible states of a [`TaskRun`] aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskRunState {
    /// Initial state after creation.
    Created,
    /// Queued for admission.
    Queued,
    /// Admitted for execution.
    Admitted,
    /// Actively running an attempt.
    Running,
    /// Waiting for approval or external input.
    Waiting,
    /// A retry is in progress.
    Retrying,
    /// A checkpoint is in progress.
    Checkpointing,
    /// Cancellation has been requested but not yet completed.
    Cancelling,
    /// A reconciliation pass is in progress.
    Reconciling,
    // ── terminal states ──────────────────────────────────────────────────
    /// Execution completed successfully.
    Succeeded,
    /// Execution failed with a reason.
    Failed,
    /// Execution was cancelled.
    Cancelled,
    /// Budget was exhausted before completion.
    BudgetExhausted,
    /// A policy denied execution.
    PolicyDenied,
    /// The task run is unrecoverable.
    Unrecoverable,
}

impl TaskRunState {
    /// Returns `true` if this is a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::BudgetExhausted
                | Self::PolicyDenied
                | Self::Unrecoverable
        )
    }
}

// ── TaskRunEventKind ───────────────────────────────────────────────────────

/// Discriminant-only representation of a [`TaskRunEvent`] — used in error
/// messages and transition table lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunEventKind {
    /// [`TaskRunEvent::TaskRunCreated`]
    TaskRunCreated,
    /// [`TaskRunEvent::TaskRunQueued`]
    TaskRunQueued,
    /// [`TaskRunEvent::TaskRunAdmitted`]
    TaskRunAdmitted,
    /// [`TaskRunEvent::AttemptStarted`]
    AttemptStarted,
    /// [`TaskRunEvent::WaitStarted`]
    WaitStarted,
    /// [`TaskRunEvent::Resumed`]
    Resumed,
    /// [`TaskRunEvent::RetryStarted`]
    RetryStarted,
    /// [`TaskRunEvent::RetryCompleted`]
    RetryCompleted,
    /// [`TaskRunEvent::CheckpointStarted`]
    CheckpointStarted,
    /// [`TaskRunEvent::CheckpointCommitted`]
    CheckpointCommitted,
    /// [`TaskRunEvent::CancellationRequested`]
    CancellationRequested,
    /// [`TaskRunEvent::CancellationCompleted`]
    CancellationCompleted,
    /// [`TaskRunEvent::TaskRunCompleted`]
    TaskRunCompleted,
    /// [`TaskRunEvent::TaskRunFailed`]
    TaskRunFailed,
    /// [`TaskRunEvent::BudgetExhausted`]
    BudgetExhausted,
    /// [`TaskRunEvent::PolicyDenied`]
    PolicyDenied,
    /// [`TaskRunEvent::ReconciliationStarted`]
    ReconciliationStarted,
    /// [`TaskRunEvent::Reconciled`]
    Reconciled,
    /// [`TaskRunEvent::Unrecoverable`]
    Unrecoverable,
    /// [`TaskRunEvent::TaskRunCancelled`]
    TaskRunCancelled,
    /// [`TaskRunEvent::LoopCycleStarted`]
    LoopCycleStarted,
    /// [`TaskRunEvent::ContextCommitted`]
    ContextCommitted,
    /// [`TaskRunEvent::PlanCommitted`]
    PlanCommitted,
    /// [`TaskRunEvent::StepOutcomeRecorded`]
    StepOutcomeRecorded,
    /// [`TaskRunEvent::LoopCycleCompleted`]
    LoopCycleCompleted,
    /// [`TaskRunEvent::NextCycleCreated`]
    NextCycleCreated,
    /// [`TaskRunEvent::RetryScheduled`]
    RetryScheduled,
    /// [`TaskRunEvent::ActivateScheduledRetryAttempt`]
    ActivateScheduledRetryAttempt,
    /// [`TaskRunEvent::RecoveryResumeStarted`]
    RecoveryResumeStarted,
    /// [`TaskRunEvent::LoopCheckpointStarted`]
    LoopCheckpointStarted,
    /// [`TaskRunEvent::LoopCheckpointRecorded`]
    LoopCheckpointRecorded,
    /// [`TaskRunEvent::LoopCheckpointCommitted`]
    LoopCheckpointCommitted,
    /// [`TaskRunEvent::LoopWakeAccepted`]
    LoopWakeAccepted,
}

// ── TaskRunEvent ───────────────────────────────────────────────────────────
