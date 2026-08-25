/// Closed, renderer-safe `TaskRun` timeline category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRunTimelineKind {
    Created,
    Queued,
    Admitted,
    AttemptStarted,
    WaitStarted,
    Resumed,
    Retrying,
    CheckpointStarted,
    CheckpointCommitted,
    CancellationRequested,
    CancellationCompleted,
    Cancelled,
    Completed,
    Failed,
    BudgetExhausted,
    PolicyDenied,
    ReconciliationStarted,
    ReconciliationCompleted,
    Unrecoverable,
    CycleStarted,
    ContextCommitted,
    PlanCommitted,
    StepOutcomeRecorded,
    CycleCompleted,
    NextCycleCreated,
    RetryScheduled,
    RetryAttemptActivated,
    RecoveryResumeStarted,
    LoopCheckpointStarted,
    LoopCheckpointRecorded,
    LoopCheckpointCommitted,
    LoopWakeAccepted,
}

impl TaskRunTimelineKind {
    pub(super) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "taskRun.created" => Self::Created,
            "taskRun.queued" => Self::Queued,
            "taskRun.admitted" => Self::Admitted,
            "taskRun.attempt.started" => Self::AttemptStarted,
            "taskRun.wait.started" => Self::WaitStarted,
            "taskRun.resumed" => Self::Resumed,
            "taskRun.retry.started" | "taskRun.retry.completed" => Self::Retrying,
            "taskRun.checkpoint.started" => Self::CheckpointStarted,
            "taskRun.checkpoint.committed" => Self::CheckpointCommitted,
            "taskRun.cancellation.requested" => Self::CancellationRequested,
            "taskRun.cancellation.completed" => Self::CancellationCompleted,
            "taskRun.cancelled" => Self::Cancelled,
            "taskRun.completed" => Self::Completed,
            "taskRun.failed" => Self::Failed,
            "taskRun.budget.exhausted" => Self::BudgetExhausted,
            "taskRun.policy.denied" => Self::PolicyDenied,
            "taskRun.reconciliation.started" => Self::ReconciliationStarted,
            "taskRun.reconciliation.completed" => Self::ReconciliationCompleted,
            "taskRun.unrecoverable" => Self::Unrecoverable,
            "taskRun.loop.cycle.started" => Self::CycleStarted,
            "taskRun.context.committed" => Self::ContextCommitted,
            "taskRun.plan.committed" => Self::PlanCommitted,
            "taskRun.step.outcome.recorded" => Self::StepOutcomeRecorded,
            "taskRun.loop.cycle.completed" => Self::CycleCompleted,
            "taskRun.next.cycle.created" => Self::NextCycleCreated,
            "taskRun.retry.scheduled" => Self::RetryScheduled,
            "taskRun.retry.attempt.activated" => Self::RetryAttemptActivated,
            "taskRun.recovery.resume.started" => Self::RecoveryResumeStarted,
            "taskRun.loop.checkpoint.started" => Self::LoopCheckpointStarted,
            "taskRun.loop.checkpoint.recorded" => Self::LoopCheckpointRecorded,
            "taskRun.loop.checkpoint.committed" => Self::LoopCheckpointCommitted,
            "taskRun.loop.wake.accepted" => Self::LoopWakeAccepted,
            _ => return None,
        })
    }

    /// Returns the fixed wire label after strict validation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Queued => "queued",
            Self::Admitted => "admitted",
            Self::AttemptStarted => "attempt_started",
            Self::WaitStarted => "wait_started",
            Self::Resumed => "resumed",
            Self::Retrying => "retrying",
            Self::CheckpointStarted => "checkpoint_started",
            Self::CheckpointCommitted => "checkpoint_committed",
            Self::CancellationRequested => "cancellation_requested",
            Self::CancellationCompleted => "cancellation_completed",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::BudgetExhausted => "budget_exhausted",
            Self::PolicyDenied => "policy_denied",
            Self::ReconciliationStarted => "reconciliation_started",
            Self::ReconciliationCompleted => "reconciliation_completed",
            Self::Unrecoverable => "unrecoverable",
            Self::CycleStarted => "cycle_started",
            Self::ContextCommitted => "context_committed",
            Self::PlanCommitted => "plan_committed",
            Self::StepOutcomeRecorded => "step_outcome_recorded",
            Self::CycleCompleted => "cycle_completed",
            Self::NextCycleCreated => "next_cycle_created",
            Self::RetryScheduled => "retry_scheduled",
            Self::RetryAttemptActivated => "retry_attempt_activated",
            Self::RecoveryResumeStarted => "recovery_resume_started",
            Self::LoopCheckpointStarted => "loop_checkpoint_started",
            Self::LoopCheckpointRecorded => "loop_checkpoint_recorded",
            Self::LoopCheckpointCommitted => "loop_checkpoint_committed",
            Self::LoopWakeAccepted => "loop_wake_accepted",
        }
    }
}

/// Validated `TaskRun` event data. It exposes no raw JSON or runtime errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRunReplayPayload {
    pub(super) kind: TaskRunTimelineKind,
    pub(super) attempt_id: Option<CanonicalId>,
}

impl TaskRunReplayPayload {
    #[must_use]
    pub const fn kind(&self) -> TaskRunTimelineKind {
        self.kind
    }

    #[must_use]
    pub const fn attempt_id(&self) -> Option<CanonicalId> {
        self.attempt_id
    }
}
