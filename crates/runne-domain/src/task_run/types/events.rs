use crate::id::{ConversationId, WorkspaceId};

/// Maximum UTF-8 byte length of a submitted task prompt.
pub const MAX_TASK_RUN_PROMPT_BYTES: usize = 65_536;

/// Validated immutable user input attached to a submitted TaskRun.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunInput(String);

impl std::fmt::Debug for TaskRunInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskRunInput")
            .field("redacted", &true)
            .finish()
    }
}

/// Invalid submitted task prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRunInputError;

impl TaskRunInput {
    /// Creates a bounded, non-blank UTF-8 prompt.
    pub fn new(prompt: String) -> Result<Self, TaskRunInputError> {
        if prompt.trim().is_empty() || prompt.len() > MAX_TASK_RUN_PROMPT_BYTES {
            return Err(TaskRunInputError);
        }
        Ok(Self(prompt))
    }

    /// Returns the submitted prompt.
    pub fn prompt(&self) -> &str {
        &self.0
    }
}

/// All events emitted by the [`TaskRun`] aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunEvent {
    /// Client submission with its immutable conversation, workspace, and prompt.
    TaskRunSubmitted {
        conversation_id: ConversationId,
        workspace_id: WorkspaceId,
        input: TaskRunInput,
    },
    /// The task run was created.
    TaskRunCreated,
    /// The task run was queued for admission.
    TaskRunQueued,
    /// The task run was admitted for execution.
    TaskRunAdmitted,
    /// A new attempt started.
    AttemptStarted {
        /// The unique attempt ID.
        attempt_id: AttemptId,
    },
    /// The task run entered a waiting state.
    WaitStarted,
    /// The task run resumed from waiting.
    Resumed,
    /// A retry was initiated.
    RetryStarted {
        /// The new attempt ID for the retry.
        attempt_id: AttemptId,
    },
    /// A retry completed and the task run returns to running.
    RetryCompleted {
        /// The attempt ID that was retried.
        attempt_id: AttemptId,
    },
    /// A checkpoint operation started.
    CheckpointStarted,
    /// A checkpoint was committed.
    CheckpointCommitted,
    /// Cancellation was requested.
    CancellationRequested,
    /// Cancellation completed.
    CancellationCompleted,
    /// The task run completed with a result.
    TaskRunCompleted {
        /// The terminal result.
        result: TerminalResult,
    },
    /// The task run failed.
    TaskRunFailed {
        /// Human-readable failure reason.
        reason: String,
    },
    /// Budget was exhausted.
    BudgetExhausted,
    /// A policy denied execution.
    PolicyDenied,
    /// Reconciliation started.
    ReconciliationStarted,
    /// Reconciliation completed.
    Reconciled,
    /// The task run is unrecoverable.
    Unrecoverable,
    /// Direct cancellation (from admitted/queued/waiting/retrying states).
    TaskRunCancelled,
    /// A loop cycle started for the active attempt.
    LoopCycleStarted {
        cycle_id: CycleId,
        attempt_id: AttemptId,
        sequence: u64,
        parent_cycle_id: Option<CycleId>,
    },
    /// An immutable context manifest was committed to the active cycle.
    ContextCommitted {
        cycle_id: CycleId,
        manifest_ref: ContextManifestRef,
    },
    /// An immutable plan revision was committed to the active cycle.
    PlanCommitted {
        cycle_id: CycleId,
        plan_revision_ref: PlanRevisionRef,
        input_digest: IntegrityDigest,
        output_digest: IntegrityDigest,
        expected_proposal_indexes: Vec<u32>,
    },
    /// One exact proposal outcome was recorded.
    StepOutcomeRecorded {
        cycle_id: CycleId,
        outcome: StepOutcomeRecord,
    },
    /// The active loop cycle reached a durable disposition.
    LoopCycleCompleted {
        cycle_id: CycleId,
        attempt_id: AttemptId,
        disposition: LoopDisposition,
    },
    /// One exact successor cycle was reserved.
    NextCycleCreated {
        parent_cycle_id: CycleId,
        successor_cycle_id: CycleId,
        attempt_id: AttemptId,
        sequence: u64,
    },
    /// A retry was scheduled without activating its new attempt.
    RetryScheduled {
        ordinal: u64,
        old_attempt_id: AttemptId,
        new_attempt_id: AttemptId,
        abandoned_cycle_id: CycleId,
        step_outcome_ref: StepOutcomeRef,
        retry_policy_digest: IntegrityDigest,
        budget_reservation_ref: BudgetReservationRef,
        delay_ms: u64,
        due_at_unix_us: i64,
    },
    /// The exact pending retry attempt was activated after its due time.
    ActivateScheduledRetryAttempt {
        ordinal: u64,
        attempt_id: AttemptId,
        activated_at_unix_us: i64,
    },
    /// Reconciliation completed and execution resumed with a new attempt.
    RecoveryResumeStarted {
        new_attempt_id: AttemptId,
        new_generation: u64,
        abandoned_cycle_id: Option<CycleId>,
        context_manifest_ref: ContextManifestRef,
        checkpoint_ref: CheckpointRef,
        reconciliation_ref: ReconciliationResultRef,
    },
    /// A loop checkpoint batch started.
    LoopCheckpointStarted {
        checkpoint_id: CheckpointId,
        event_position: u64,
        integrity_digest: IntegrityDigest,
    },
    /// The canonical loop checkpoint body was recorded.
    LoopCheckpointRecorded {
        checkpoint_id: CheckpointId,
        event_position: u64,
        body: LoopCheckpointBody,
        integrity_digest: IntegrityDigest,
    },
    /// A loop checkpoint batch committed.
    LoopCheckpointCommitted {
        checkpoint_id: CheckpointId,
        event_position: u64,
        integrity_digest: IntegrityDigest,
    },
    /// Exact wake evidence was accepted for the pending loop wait.
    LoopWakeAccepted {
        cycle_id: CycleId,
        wake_evidence_ref: WakeEvidenceRef,
    },
}

impl TaskRunEvent {
    /// Return the discriminant kind for this event.
    pub fn kind(&self) -> TaskRunEventKind {
        match self {
            Self::TaskRunSubmitted { .. } => TaskRunEventKind::TaskRunCreated,
            Self::TaskRunCreated => TaskRunEventKind::TaskRunCreated,
            Self::TaskRunQueued => TaskRunEventKind::TaskRunQueued,
            Self::TaskRunAdmitted => TaskRunEventKind::TaskRunAdmitted,
            Self::AttemptStarted { .. } => TaskRunEventKind::AttemptStarted,
            Self::WaitStarted => TaskRunEventKind::WaitStarted,
            Self::Resumed => TaskRunEventKind::Resumed,
            Self::RetryStarted { .. } => TaskRunEventKind::RetryStarted,
            Self::RetryCompleted { .. } => TaskRunEventKind::RetryCompleted,
            Self::CheckpointStarted => TaskRunEventKind::CheckpointStarted,
            Self::CheckpointCommitted => TaskRunEventKind::CheckpointCommitted,
            Self::CancellationRequested => TaskRunEventKind::CancellationRequested,
            Self::CancellationCompleted => TaskRunEventKind::CancellationCompleted,
            Self::TaskRunCompleted { .. } => TaskRunEventKind::TaskRunCompleted,
            Self::TaskRunFailed { .. } => TaskRunEventKind::TaskRunFailed,
            Self::BudgetExhausted => TaskRunEventKind::BudgetExhausted,
            Self::PolicyDenied => TaskRunEventKind::PolicyDenied,
            Self::ReconciliationStarted => TaskRunEventKind::ReconciliationStarted,
            Self::Reconciled => TaskRunEventKind::Reconciled,
            Self::Unrecoverable => TaskRunEventKind::Unrecoverable,
            Self::TaskRunCancelled => TaskRunEventKind::TaskRunCancelled,
            Self::LoopCycleStarted { .. } => TaskRunEventKind::LoopCycleStarted,
            Self::ContextCommitted { .. } => TaskRunEventKind::ContextCommitted,
            Self::PlanCommitted { .. } => TaskRunEventKind::PlanCommitted,
            Self::StepOutcomeRecorded { .. } => TaskRunEventKind::StepOutcomeRecorded,
            Self::LoopCycleCompleted { .. } => TaskRunEventKind::LoopCycleCompleted,
            Self::NextCycleCreated { .. } => TaskRunEventKind::NextCycleCreated,
            Self::RetryScheduled { .. } => TaskRunEventKind::RetryScheduled,
            Self::ActivateScheduledRetryAttempt { .. } => {
                TaskRunEventKind::ActivateScheduledRetryAttempt
            }
            Self::RecoveryResumeStarted { .. } => TaskRunEventKind::RecoveryResumeStarted,
            Self::LoopCheckpointStarted { .. } => TaskRunEventKind::LoopCheckpointStarted,
            Self::LoopCheckpointRecorded { .. } => TaskRunEventKind::LoopCheckpointRecorded,
            Self::LoopCheckpointCommitted { .. } => TaskRunEventKind::LoopCheckpointCommitted,
            Self::LoopWakeAccepted { .. } => TaskRunEventKind::LoopWakeAccepted,
        }
    }
}
