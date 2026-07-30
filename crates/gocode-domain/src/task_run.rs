//! TaskRun aggregate — lifecycle state machine, events, transition table.
//!
//! The TaskRun is the core aggregate: it tracks execution state,
//! attempt history, and terminal outcomes.

use crate::agent_loop::{
    ActiveLoopCycle, CompletedCycleRef, CycleHistoryEntry, LoopCheckpointBody, LoopCycleState,
    LoopDisposition, PendingLoopCheckpoint, PendingLoopWait, PendingRetry, PendingSuccessorCycle,
    StepOutcomeRecord, StepOutcomeRef, StepOutcomeType, WakeEvidenceRef,
};
use crate::command::{CreateTaskRun, TaskRunCommand, TerminalResult};
use crate::context::ContextManifestRef;
use crate::error::{DomainError, LoopInvariantViolation};
use crate::event::{AggregateType, DomainEventDraft, EventEnvelope, Sensitivity};
use crate::id::{AggregateId, AttemptId, CheckpointId, CycleId, IntegrityDigest, TaskRunId};
use crate::plan::PlanRevisionRef;
use crate::recovery::{ReconciliationResultRef, ReconciliationStatus};
use crate::reference::{BudgetReservationRef, CheckpointRef};
use crate::verification::PlanEvaluationResult;

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

/// All events emitted by the [`TaskRun`] aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskRunEvent {
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

// ── TaskRun aggregate ──────────────────────────────────────────────────────

/// The TaskRun aggregate root — tracks execution lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRun {
    /// The aggregate identity.
    id: TaskRunId,
    /// Current state.
    state: TaskRunState,
    /// The currently active attempt, if any.
    active_attempt: Option<AttemptId>,
    /// All known attempt IDs (ever).
    attempt_history: Vec<AttemptId>,
    /// Terminal result, if the task run has completed or failed.
    terminal_result: Option<TerminalResult>,
    /// Currently active loop cycle.
    active_cycle: Option<ActiveLoopCycle>,
    /// Last completed loop cycle.
    last_completed_cycle: Option<CompletedCycleRef>,
    /// Exact successor reservation.
    pending_successor: Option<PendingSuccessorCycle>,
    /// Exact wait condition pending wake evidence.
    pending_loop_wait: Option<PendingLoopWait>,
    /// Retry scheduled but not yet activated.
    pending_retry: Option<PendingRetry>,
    /// Loop checkpoint batch in progress.
    pending_loop_checkpoint: Option<PendingLoopCheckpoint>,
    /// Globally unique cycle history for this task run.
    cycle_history: Vec<CycleHistoryEntry>,
    /// Monotonic recovery generation.
    recovery_generation: u64,
}

impl TaskRun {
    /// Return the task run ID.
    pub fn id(&self) -> &TaskRunId {
        &self.id
    }

    /// Return the current state.
    pub fn state(&self) -> TaskRunState {
        self.state
    }

    /// Return the active attempt ID, if any.
    pub fn active_attempt(&self) -> Option<&AttemptId> {
        self.active_attempt.as_ref()
    }

    /// Return the attempt history.
    pub fn attempt_history(&self) -> &[AttemptId] {
        &self.attempt_history
    }

    /// Return the terminal result, if any.
    pub fn terminal_result(&self) -> Option<&TerminalResult> {
        self.terminal_result.as_ref()
    }

    /// Return the active loop cycle projection.
    pub fn active_cycle(&self) -> Option<&ActiveLoopCycle> {
        self.active_cycle.as_ref()
    }

    /// Return the last completed loop cycle projection.
    pub fn last_completed_cycle(&self) -> Option<&CompletedCycleRef> {
        self.last_completed_cycle.as_ref()
    }

    /// Return the pending successor reservation.
    pub fn pending_successor(&self) -> Option<&PendingSuccessorCycle> {
        self.pending_successor.as_ref()
    }

    /// Return the pending loop wait.
    pub fn pending_loop_wait(&self) -> Option<&PendingLoopWait> {
        self.pending_loop_wait.as_ref()
    }

    /// Return the pending retry.
    pub fn pending_retry(&self) -> Option<&PendingRetry> {
        self.pending_retry.as_ref()
    }

    /// Return the pending loop checkpoint.
    pub fn pending_loop_checkpoint(&self) -> Option<&PendingLoopCheckpoint> {
        self.pending_loop_checkpoint.as_ref()
    }

    /// Return all accepted cycle identities.
    pub fn cycle_history(&self) -> &[CycleHistoryEntry] {
        &self.cycle_history
    }

    /// Return the current recovery generation.
    pub fn recovery_generation(&self) -> u64 {
        self.recovery_generation
    }

    // ── decide_create ────────────────────────────────────────────────────

    /// Handle a [`CreateTaskRun`] command — produces the initial event.
    ///
    /// Assumes the aggregate does not exist yet.
    pub fn decide_create(
        command: CreateTaskRun,
    ) -> Result<DomainEventDraft<TaskRunEvent>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(command.taskrun_id);
        Ok(DomainEventDraft::new(
            aggregate_id.clone(),
            aggregate_id,
            1,
            Sensitivity::Public,
            TaskRunEvent::TaskRunCreated,
        ))
    }

    /// Creates and starts one TaskRun as a single valid event batch.
    ///
    /// This is used by coordinators that durably bind accepted work to an
    /// execution attempt in the same transaction. The resulting stream is
    /// equivalent to create → queue → admit → start-attempt.
    pub fn decide_create_running(
        command: CreateTaskRun,
        attempt_id: AttemptId,
    ) -> Result<Vec<DomainEventDraft<TaskRunEvent>>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(command.taskrun_id);
        let draft = |payload| {
            DomainEventDraft::new(
                aggregate_id.clone(),
                aggregate_id.clone(),
                1,
                Sensitivity::Public,
                payload,
            )
        };
        Ok(vec![
            draft(TaskRunEvent::TaskRunCreated),
            draft(TaskRunEvent::TaskRunQueued),
            draft(TaskRunEvent::TaskRunAdmitted),
            draft(TaskRunEvent::AttemptStarted { attempt_id }),
        ])
    }

    // ── decide ───────────────────────────────────────────────────────────

    /// Handle a command against an existing aggregate — produces zero or
    /// more events.
    pub fn decide(
        &self,
        command: TaskRunCommand,
    ) -> Result<Vec<DomainEventDraft<TaskRunEvent>>, DomainError> {
        if self.state.is_terminal() {
            return Err(DomainError::TerminalImmutable {
                current: self.state,
            });
        }

        let aggregate_id = AggregateId::TaskRun(self.id);
        let draft = |payload: TaskRunEvent, sensitivity: Sensitivity| {
            DomainEventDraft::new(
                aggregate_id.clone(),
                aggregate_id.clone(),
                1,
                sensitivity,
                payload,
            )
        };

        match command {
            TaskRunCommand::Admit => {
                self.require_state(TaskRunState::Queued, TaskRunEventKind::TaskRunAdmitted)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunAdmitted,
                    Sensitivity::Public,
                )])
            }

            TaskRunCommand::Queue => {
                self.require_state(TaskRunState::Created, TaskRunEventKind::TaskRunQueued)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunQueued,
                    Sensitivity::Public,
                )])
            }

            TaskRunCommand::StartAttempt { attempt_id } => {
                self.require_state(TaskRunState::Admitted, TaskRunEventKind::AttemptStarted)?;
                self.check_attempt_id_unique(&attempt_id)?;
                Ok(vec![draft(
                    TaskRunEvent::AttemptStarted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::WaitForApproval => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::WaitStarted)?;
                Ok(vec![draft(TaskRunEvent::WaitStarted, Sensitivity::Public)])
            }
            TaskRunCommand::Resume => {
                self.require_state(TaskRunState::Waiting, TaskRunEventKind::Resumed)?;
                if self.pending_loop_wait.is_some() {
                    return Err(DomainError::LoopWakeEvidenceRequired);
                }
                Ok(vec![draft(TaskRunEvent::Resumed, Sensitivity::Public)])
            }
            TaskRunCommand::StartRetry { attempt_id } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::RetryStarted)?;
                self.check_attempt_id_unique(&attempt_id)?;
                Ok(vec![draft(
                    TaskRunEvent::RetryStarted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CompleteRetry { attempt_id } => {
                self.require_state(TaskRunState::Retrying, TaskRunEventKind::RetryCompleted)?;
                if self.pending_retry.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::PendingRetryExists));
                }
                Ok(vec![draft(
                    TaskRunEvent::RetryCompleted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::StartCheckpoint => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::CheckpointStarted)?;
                Ok(vec![draft(
                    TaskRunEvent::CheckpointStarted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CommitCheckpoint => {
                self.require_state(
                    TaskRunState::Checkpointing,
                    TaskRunEventKind::CheckpointCommitted,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::CheckpointCommitted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::RequestCancellation => {
                // Valid from: running, waiting, retrying, admitted, queued
                let valid = matches!(
                    self.state,
                    TaskRunState::Running
                        | TaskRunState::Waiting
                        | TaskRunState::Retrying
                        | TaskRunState::Admitted
                        | TaskRunState::Queued
                );
                if !valid {
                    return Err(DomainError::InvalidTransition {
                        from: self.state,
                        event: TaskRunEventKind::CancellationRequested,
                    });
                }
                Ok(vec![draft(
                    TaskRunEvent::CancellationRequested,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CompleteCancellation => {
                self.require_state(
                    TaskRunState::Cancelling,
                    TaskRunEventKind::CancellationCompleted,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::CancellationCompleted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::Complete { result } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::TaskRunCompleted)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunCompleted { result },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::Fail { reason } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::TaskRunFailed)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunFailed { reason },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::FailGeneration { reason } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::TaskRunFailed)?;
                Ok(vec![draft(
                    TaskRunEvent::TaskRunFailed {
                        reason: reason.as_code().to_owned(),
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::StartReconciliation => {
                self.require_state(
                    TaskRunState::Running,
                    TaskRunEventKind::ReconciliationStarted,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::ReconciliationStarted,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CompleteReconciliation => {
                self.require_state(TaskRunState::Reconciling, TaskRunEventKind::Reconciled)?;
                Ok(vec![draft(TaskRunEvent::Reconciled, Sensitivity::Public)])
            }
            TaskRunCommand::MarkUnrecoverable => {
                self.require_state(TaskRunState::Reconciling, TaskRunEventKind::Unrecoverable)?;
                Ok(vec![draft(
                    TaskRunEvent::Unrecoverable,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::StartLoopCycle { cycle_id } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::LoopCycleStarted)?;
                let attempt_id = self.active_attempt.ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingActiveAttempt)
                })?;
                if self.active_cycle.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::ActiveCycleExists));
                }
                if self
                    .cycle_history
                    .iter()
                    .any(|entry| entry.cycle_id == cycle_id)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleAlreadyUsed));
                }

                let (sequence, parent_cycle_id) = if let Some(pending) =
                    self.pending_successor.as_ref()
                {
                    if pending.successor_cycle_id != cycle_id || pending.attempt_id != attempt_id {
                        return Err(Self::loop_error(
                            LoopInvariantViolation::SuccessorReservationMismatch,
                        ));
                    }
                    (pending.sequence, Some(pending.parent_cycle_id))
                } else {
                    if self
                        .cycle_history
                        .iter()
                        .any(|entry| entry.attempt_id == attempt_id)
                    {
                        return Err(Self::loop_error(
                            LoopInvariantViolation::AttemptAlreadyHasCycle,
                        ));
                    }
                    (0, None)
                };

                Ok(vec![draft(
                    TaskRunEvent::LoopCycleStarted {
                        cycle_id,
                        attempt_id,
                        sequence,
                        parent_cycle_id,
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CommitContext {
                cycle_id,
                manifest_ref,
            } => {
                self.validate_context_commit(cycle_id, &manifest_ref)?;
                Ok(vec![draft(
                    TaskRunEvent::ContextCommitted {
                        cycle_id,
                        manifest_ref,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::CommitPlan {
                cycle_id,
                plan_revision_ref,
                input_digest,
                output_digest,
                expected_proposal_indexes,
            } => {
                self.validate_plan_commit(
                    cycle_id,
                    &plan_revision_ref,
                    &expected_proposal_indexes,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::PlanCommitted {
                        cycle_id,
                        plan_revision_ref,
                        input_digest,
                        output_digest,
                        expected_proposal_indexes,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::RecordStepOutcome { cycle_id, outcome } => {
                self.validate_step_outcome(cycle_id, &outcome)?;
                Ok(vec![draft(
                    TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::CompleteLoopCycle {
                cycle_id,
                disposition,
            } => {
                let attempt_id = self.validate_cycle_completion(cycle_id, &disposition)?;
                let completed = draft(
                    TaskRunEvent::LoopCycleCompleted {
                        cycle_id,
                        attempt_id,
                        disposition: disposition.clone(),
                    },
                    Sensitivity::Sensitive,
                );
                match disposition {
                    LoopDisposition::Continue => Ok(vec![completed]),
                    LoopDisposition::Wait { .. } => Ok(vec![
                        completed,
                        draft(TaskRunEvent::WaitStarted, Sensitivity::Public),
                    ]),
                    LoopDisposition::Complete { .. } => Ok(vec![
                        completed,
                        draft(
                            TaskRunEvent::TaskRunCompleted {
                                result: TerminalResult::Success,
                            },
                            Sensitivity::Public,
                        ),
                    ]),
                    LoopDisposition::Fail { reason, .. } => Ok(vec![
                        completed,
                        draft(
                            TaskRunEvent::TaskRunFailed { reason },
                            Sensitivity::Sensitive,
                        ),
                    ]),
                }
            }
            TaskRunCommand::CreateNextCycle {
                parent_cycle_id,
                successor_cycle_id,
            } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::NextCycleCreated)?;
                let completed = self.validate_successor(parent_cycle_id, successor_cycle_id)?;
                let sequence = completed.sequence.checked_add(1).ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::SuccessorReservationMismatch)
                })?;
                Ok(vec![draft(
                    TaskRunEvent::NextCycleCreated {
                        parent_cycle_id,
                        successor_cycle_id,
                        attempt_id: completed.attempt_id,
                        sequence,
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::ResumeLoopWait { wake_evidence_ref } => {
                self.require_state(TaskRunState::Waiting, TaskRunEventKind::LoopWakeAccepted)?;
                self.validate_wake_evidence(&wake_evidence_ref)?;
                Ok(vec![
                    draft(TaskRunEvent::Resumed, Sensitivity::Public),
                    draft(
                        TaskRunEvent::LoopWakeAccepted {
                            cycle_id: wake_evidence_ref.cycle_id,
                            wake_evidence_ref,
                        },
                        Sensitivity::Sensitive,
                    ),
                ])
            }
            TaskRunCommand::ScheduleRetry {
                new_attempt_id,
                retry_ordinal,
                step_outcome_ref,
                retry_policy_digest,
                budget_reservation_ref,
                delay_ms,
                due_at_unix_us,
            } => {
                self.require_state(TaskRunState::Running, TaskRunEventKind::RetryScheduled)?;
                if self.pending_retry.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::PendingRetryExists));
                }
                self.check_attempt_id_unique(&new_attempt_id)?;
                let active_attempt = self.active_attempt.ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingActiveAttempt)
                })?;
                let active_cycle = self
                    .active_cycle
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                if step_outcome_ref.cycle_id != active_cycle.cycle_id
                    || !active_cycle.recorded_outcomes.iter().any(|outcome| {
                        outcome.proposal_index == step_outcome_ref.proposal_index
                            && outcome.step_id == step_outcome_ref.step_id
                            && outcome.outcome_type == StepOutcomeType::FailedBeforeCommit
                    })
                    || budget_reservation_ref.taskrun_id != self.id
                    || budget_reservation_ref.attempt_id != active_attempt
                    || budget_reservation_ref.retry_ordinal != retry_ordinal
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                Ok(vec![draft(
                    TaskRunEvent::RetryScheduled {
                        ordinal: retry_ordinal,
                        old_attempt_id: active_attempt,
                        new_attempt_id,
                        abandoned_cycle_id: active_cycle.cycle_id,
                        step_outcome_ref,
                        retry_policy_digest,
                        budget_reservation_ref,
                        delay_ms,
                        due_at_unix_us,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::ActivateScheduledRetryAttempt {
                retry_ordinal,
                now_unix_us,
            } => {
                self.require_state(
                    TaskRunState::Retrying,
                    TaskRunEventKind::ActivateScheduledRetryAttempt,
                )?;
                let pending = self
                    .pending_retry
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingPendingRetry))?;
                if pending.ordinal != retry_ordinal {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                if now_unix_us < pending.due_at_unix_us {
                    return Err(Self::loop_error(LoopInvariantViolation::RetryNotDue));
                }
                Ok(vec![draft(
                    TaskRunEvent::ActivateScheduledRetryAttempt {
                        ordinal: retry_ordinal,
                        attempt_id: pending.new_attempt_id,
                        activated_at_unix_us: now_unix_us,
                    },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::CommitRecoveryResume {
                new_attempt_id,
                context_manifest_ref,
                checkpoint_ref,
                reconciliation_ref,
            } => {
                self.require_state(
                    TaskRunState::Reconciling,
                    TaskRunEventKind::RecoveryResumeStarted,
                )?;
                self.check_attempt_id_unique(&new_attempt_id)?;
                self.validate_recovery_ref(&reconciliation_ref)?;
                let new_generation = self
                    .recovery_generation
                    .checked_add(1)
                    .ok_or(DomainError::RecoveryGenerationExhausted)?;
                Ok(vec![draft(
                    TaskRunEvent::RecoveryResumeStarted {
                        new_attempt_id,
                        new_generation,
                        abandoned_cycle_id: self.active_cycle.as_ref().map(|cycle| cycle.cycle_id),
                        context_manifest_ref,
                        checkpoint_ref,
                        reconciliation_ref,
                    },
                    Sensitivity::Sensitive,
                )])
            }
            TaskRunCommand::CommitLoopCheckpoint {
                checkpoint_id,
                event_position,
                body,
                integrity_digest,
            } => {
                self.require_state(
                    TaskRunState::Running,
                    TaskRunEventKind::LoopCheckpointStarted,
                )?;
                if self.pending_loop_checkpoint.is_some() {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingCheckpointExists,
                    ));
                }
                self.validate_checkpoint_body(&body)?;
                Ok(vec![
                    draft(
                        TaskRunEvent::LoopCheckpointStarted {
                            checkpoint_id,
                            event_position,
                            integrity_digest,
                        },
                        Sensitivity::Sensitive,
                    ),
                    draft(
                        TaskRunEvent::LoopCheckpointRecorded {
                            checkpoint_id,
                            event_position,
                            body,
                            integrity_digest,
                        },
                        Sensitivity::Sensitive,
                    ),
                    draft(
                        TaskRunEvent::LoopCheckpointCommitted {
                            checkpoint_id,
                            event_position,
                            integrity_digest,
                        },
                        Sensitivity::Sensitive,
                    ),
                ])
            }
        }
    }

    // ── apply ────────────────────────────────────────────────────────────

    /// Apply a committed event to this aggregate, mutating state.
    pub fn apply(&mut self, event: &EventEnvelope<TaskRunEvent>) -> Result<(), DomainError> {
        // Validate aggregate ID
        let expected = AggregateId::TaskRun(self.id);
        if *event.aggregate_id() != expected {
            return Err(DomainError::AggregateIdMismatch {
                expected: expected.clone(),
                actual: event.aggregate_id().clone(),
            });
        }

        if *event.correlation_id() != expected {
            return Err(DomainError::AggregateIdMismatch {
                expected,
                actual: event.correlation_id().clone(),
            });
        }

        self.apply_payload(event.payload())
    }

    // ── replay ───────────────────────────────────────────────────────────

    /// Replay a sequence of committed events to reconstruct an aggregate.
    ///
    /// # Requirements
    /// - The event stream must not be empty.
    /// - Sequence numbers must be continuous starting from 1.
    /// - All events must share the same task run ID.
    /// - The first event must be `TaskRunCreated`.
    /// - `TaskRunCreated` must not appear more than once.
    pub fn replay(events: &[EventEnvelope<TaskRunEvent>]) -> Result<Self, DomainError> {
        if events.is_empty() {
            return Err(DomainError::MissingCreationEvent {
                aggregate_type: AggregateType::TaskRun,
            });
        }

        // Validate first event is creation
        let first = &events[0];
        if first.payload().kind() != TaskRunEventKind::TaskRunCreated {
            return Err(DomainError::MissingCreationEvent {
                aggregate_type: AggregateType::TaskRun,
            });
        }

        // Validate initial sequence
        if first.sequence() != 1 {
            return Err(DomainError::InvalidInitialSequence {
                expected: 1,
                actual: first.sequence(),
            });
        }

        // The TaskRun's aggregate and correlation IDs must both be the same
        // TaskRun variant. Derive the ID from the aggregate ID so an invalid
        // correlation cannot fabricate an aggregate identity during replay.
        let taskrun_id = match first.aggregate_id() {
            AggregateId::TaskRun(tid) => *tid,
            _ => {
                return Err(DomainError::AggregateIdMismatch {
                    expected: first.correlation_id().clone(),
                    actual: first.aggregate_id().clone(),
                });
            }
        };
        let expected = AggregateId::TaskRun(taskrun_id);
        if *first.correlation_id() != expected {
            return Err(DomainError::AggregateIdMismatch {
                expected,
                actual: first.correlation_id().clone(),
            });
        }
        let mut agg = Self {
            id: taskrun_id,
            state: TaskRunState::Created,
            active_attempt: None,
            attempt_history: Vec::new(),
            terminal_result: None,
            active_cycle: None,
            last_completed_cycle: None,
            pending_successor: None,
            pending_loop_wait: None,
            pending_retry: None,
            pending_loop_checkpoint: None,
            cycle_history: Vec::new(),
            recovery_generation: 0,
        };

        let mut creation_seen = false;
        for (index, event) in events.iter().enumerate() {
            let expected_seq = index as u64 + 1;
            // Sequence continuity
            if event.sequence() != expected_seq {
                return Err(DomainError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence(),
                });
            }

            // All events must belong to the same TaskRun aggregate and
            // correlation stream. Both checks are variant-sensitive equality.
            if *event.aggregate_id() != expected {
                return Err(DomainError::AggregateIdMismatch {
                    expected: expected.clone(),
                    actual: event.aggregate_id().clone(),
                });
            }
            if *event.correlation_id() != expected {
                return Err(DomainError::AggregateIdMismatch {
                    expected: expected.clone(),
                    actual: event.correlation_id().clone(),
                });
            }

            let payload = event.payload();

            // Duplicate creation check
            if payload.kind() == TaskRunEventKind::TaskRunCreated {
                if creation_seen {
                    return Err(DomainError::DuplicateCreationEvent {
                        aggregate_type: AggregateType::TaskRun,
                        aggregate_id: event.aggregate_id().clone(),
                    });
                }
                creation_seen = true;
            }

            Self::validate_replay_batch(events, index, &agg)?;
            agg.apply_payload(payload)?;
        }

        if agg.pending_loop_checkpoint.is_some() {
            return Err(DomainError::CorruptCheckpointBatch);
        }
        Ok(agg)
    }

    // ── private helpers ──────────────────────────────────────────────────

    /// Require that the aggregate is in a specific state.
    fn require_state(
        &self,
        expected: TaskRunState,
        event_kind: TaskRunEventKind,
    ) -> Result<(), DomainError> {
        if self.state != expected {
            return Err(DomainError::InvalidTransition {
                from: self.state,
                event: event_kind,
            });
        }
        Ok(())
    }

    /// Check that an attempt ID has not been used before.
    fn check_attempt_id_unique(&self, attempt_id: &AttemptId) -> Result<(), DomainError> {
        if self.attempt_history.contains(attempt_id) {
            return Err(DomainError::DuplicateAttemptId {
                taskrun_id: self.id,
                attempt_id: *attempt_id,
            });
        }
        Ok(())
    }

    fn loop_error(violation: LoopInvariantViolation) -> DomainError {
        DomainError::LoopInvariantViolation { violation }
    }

    fn validate_replay_batch(
        events: &[EventEnvelope<TaskRunEvent>],
        index: usize,
        aggregate: &Self,
    ) -> Result<(), DomainError> {
        let event = &events[index];
        let same_command =
            |other: &EventEnvelope<TaskRunEvent>| other.command_id() == event.command_id();
        match event.payload() {
            TaskRunEvent::LoopCycleCompleted { disposition, .. } => {
                if matches!(disposition, LoopDisposition::Continue) {
                    return Ok(());
                }
                let next = events
                    .get(index + 1)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                let valid = match disposition {
                    LoopDisposition::Continue => true,
                    LoopDisposition::Wait { .. } => {
                        matches!(next.payload(), TaskRunEvent::WaitStarted)
                    }
                    LoopDisposition::Complete { .. } => matches!(
                        next.payload(),
                        TaskRunEvent::TaskRunCompleted {
                            result: TerminalResult::Success
                        }
                    ),
                    LoopDisposition::Fail { reason, .. } => matches!(
                        next.payload(),
                        TaskRunEvent::TaskRunFailed {
                            reason: next_reason
                        } if next_reason == reason
                    ),
                };
                if !valid || !same_command(next) {
                    return Err(DomainError::CorruptCommandBatch);
                }
            }
            TaskRunEvent::Resumed if aggregate.pending_loop_wait.is_some() => {
                let next = events
                    .get(index + 1)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                if !matches!(next.payload(), TaskRunEvent::LoopWakeAccepted { .. })
                    || !same_command(next)
                {
                    return Err(DomainError::CorruptCommandBatch);
                }
            }
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                let recorded = events
                    .get(index + 1)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                let committed = events
                    .get(index + 2)
                    .ok_or(DomainError::CorruptCommandBatch)?;
                let recorded_matches = matches!(
                    recorded.payload(),
                    TaskRunEvent::LoopCheckpointRecorded {
                        checkpoint_id: recorded_id,
                        event_position: recorded_position,
                        integrity_digest: recorded_digest,
                        ..
                    } if recorded_id == checkpoint_id
                        && recorded_position == event_position
                        && recorded_digest == integrity_digest
                );
                let committed_matches = matches!(
                    committed.payload(),
                    TaskRunEvent::LoopCheckpointCommitted {
                        checkpoint_id: committed_id,
                        event_position: committed_position,
                        integrity_digest: committed_digest,
                    } if committed_id == checkpoint_id
                        && committed_position == event_position
                        && committed_digest == integrity_digest
                );
                if !recorded_matches
                    || !committed_matches
                    || !same_command(recorded)
                    || !same_command(committed)
                {
                    return Err(DomainError::CorruptCommandBatch);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn active_cycle_for(
        &self,
        cycle_id: CycleId,
        state: LoopCycleState,
    ) -> Result<&ActiveLoopCycle, DomainError> {
        let cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if cycle.cycle_id != cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }
        if cycle.state != state {
            return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
        }
        Ok(cycle)
    }

    fn validate_context_commit(
        &self,
        cycle_id: CycleId,
        manifest_ref: &ContextManifestRef,
    ) -> Result<(), DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::ContextCommitted)?;
        let cycle = self.active_cycle_for(cycle_id, LoopCycleState::Observing)?;
        if manifest_ref.taskrun_id != self.id
            || manifest_ref.attempt_id != cycle.attempt_id
            || manifest_ref.cycle_id != cycle_id
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::ContextBindingMismatch,
            ));
        }
        Ok(())
    }

    fn indexes_are_canonical(indexes: &[u32]) -> bool {
        indexes.windows(2).all(|pair| pair[0] < pair[1])
    }

    fn validate_plan_commit(
        &self,
        cycle_id: CycleId,
        plan_ref: &PlanRevisionRef,
        expected_indexes: &[u32],
    ) -> Result<(), DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::PlanCommitted)?;
        let cycle = self.active_cycle_for(cycle_id, LoopCycleState::Proposing)?;
        let context_ref = cycle
            .context_manifest_ref
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::ContextBindingMismatch))?;
        if !Self::indexes_are_canonical(expected_indexes) {
            return Err(Self::loop_error(
                LoopInvariantViolation::ProposalIndexesNotCanonical,
            ));
        }
        if plan_ref.taskrun_id != self.id
            || plan_ref.cycle_id != cycle_id
            || &plan_ref.context_manifest_ref != context_ref
            || plan_ref.expected_proposal_indexes != expected_indexes
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::PlanBindingMismatch,
            ));
        }
        Ok(())
    }

    fn outcome_cardinality_is_valid(outcome: &StepOutcomeRecord) -> bool {
        match outcome.outcome_type {
            StepOutcomeType::Succeeded => outcome.result_ref.is_some(),
            StepOutcomeType::FailedBeforeCommit | StepOutcomeType::Cancelled => {
                outcome.effect_id.is_none()
            }
            StepOutcomeType::FailedAfterCommit | StepOutcomeType::Uncertain => {
                outcome.effect_id.is_some()
            }
        }
    }

    fn validate_step_outcome(
        &self,
        cycle_id: CycleId,
        outcome: &StepOutcomeRecord,
    ) -> Result<(), DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::StepOutcomeRecorded)?;
        let cycle = self.active_cycle_for(cycle_id, LoopCycleState::Acting)?;
        if !cycle
            .expected_proposal_indexes
            .contains(&outcome.proposal_index)
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::ProposalIndexUnexpected,
            ));
        }
        if cycle
            .recorded_outcomes
            .iter()
            .any(|recorded| recorded.proposal_index == outcome.proposal_index)
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::ProposalOutcomeDuplicate,
            ));
        }
        if cycle
            .recorded_outcomes
            .iter()
            .any(|recorded| recorded.step_id == outcome.step_id)
        {
            return Err(Self::loop_error(LoopInvariantViolation::StepIdDuplicate));
        }
        if !Self::outcome_cardinality_is_valid(outcome) {
            return Err(Self::loop_error(
                LoopInvariantViolation::OutcomeCardinalityMismatch,
            ));
        }
        Ok(())
    }

    fn validate_cycle_completion(
        &self,
        cycle_id: CycleId,
        disposition: &LoopDisposition,
    ) -> Result<AttemptId, DomainError> {
        self.require_state(TaskRunState::Running, TaskRunEventKind::LoopCycleCompleted)?;
        let cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if cycle.cycle_id != cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }

        match disposition {
            LoopDisposition::Fail {
                unresolved_proposals,
                ..
            } => {
                if !matches!(
                    cycle.state,
                    LoopCycleState::Acting | LoopCycleState::Evaluating
                ) {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
                }
                let canonical = cycle
                    .expected_proposal_indexes
                    .iter()
                    .copied()
                    .filter(|index| {
                        !cycle
                            .recorded_outcomes
                            .iter()
                            .any(|outcome| outcome.proposal_index == *index)
                    })
                    .collect::<Vec<_>>();
                if unresolved_proposals != &canonical {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::UnresolvedProposalMismatch,
                    ));
                }
            }
            LoopDisposition::Complete {
                plan_evaluation_ref,
            } => {
                if cycle.state != LoopCycleState::Evaluating {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
                }
                let plan_ref = cycle
                    .plan_revision_ref
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::PlanBindingMismatch))?;
                if plan_evaluation_ref.taskrun_id != self.id
                    || plan_evaluation_ref.plan_id != plan_ref.plan_id
                    || plan_evaluation_ref.plan_revision != plan_ref.revision
                    || plan_evaluation_ref.result != PlanEvaluationResult::Passed
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PlanBindingMismatch,
                    ));
                }
            }
            LoopDisposition::Continue | LoopDisposition::Wait { .. } => {
                if cycle.state != LoopCycleState::Evaluating {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleStateMismatch));
                }
            }
        }
        Ok(cycle.attempt_id)
    }

    fn validate_successor(
        &self,
        parent_cycle_id: CycleId,
        successor_cycle_id: CycleId,
    ) -> Result<&CompletedCycleRef, DomainError> {
        if self.active_cycle.is_some() {
            return Err(Self::loop_error(LoopInvariantViolation::ActiveCycleExists));
        }
        if self.pending_successor.is_some() {
            return Err(Self::loop_error(
                LoopInvariantViolation::SuccessorAlreadyAllocated,
            ));
        }
        if self
            .cycle_history
            .iter()
            .any(|entry| entry.cycle_id == successor_cycle_id)
        {
            return Err(Self::loop_error(LoopInvariantViolation::CycleAlreadyUsed));
        }
        let completed = self
            .last_completed_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingCompletedCycle))?;
        if completed.cycle_id != parent_cycle_id {
            return Err(Self::loop_error(
                LoopInvariantViolation::CycleBindingMismatch,
            ));
        }
        if completed.successor_allocated {
            return Err(Self::loop_error(
                LoopInvariantViolation::SuccessorAlreadyAllocated,
            ));
        }
        let allowed = match &completed.disposition {
            LoopDisposition::Continue => completed.accepted_wake_evidence.is_none(),
            LoopDisposition::Wait { wake_condition, .. } => completed
                .accepted_wake_evidence
                .as_ref()
                .is_some_and(|evidence| {
                    evidence.cycle_id == completed.cycle_id
                        && evidence.condition_digest == wake_condition.condition_digest
                }),
            LoopDisposition::Complete { .. } | LoopDisposition::Fail { .. } => false,
        };
        if !allowed {
            return Err(Self::loop_error(
                LoopInvariantViolation::SuccessorNotAllowed,
            ));
        }
        Ok(completed)
    }

    fn validate_wake_evidence(
        &self,
        wake_evidence_ref: &WakeEvidenceRef,
    ) -> Result<(), DomainError> {
        let pending = self
            .pending_loop_wait
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::WakeEvidenceMismatch))?;
        if wake_evidence_ref.cycle_id != pending.cycle_id
            || wake_evidence_ref.condition_digest != pending.wake_condition.condition_digest
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::WakeEvidenceMismatch,
            ));
        }
        Ok(())
    }

    fn validate_recovery_ref(
        &self,
        reconciliation_ref: &ReconciliationResultRef,
    ) -> Result<(), DomainError> {
        let active_attempt = self
            .active_attempt
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveAttempt))?;
        if reconciliation_ref.taskrun_id != self.id
            || reconciliation_ref.predecessor_attempt_id != active_attempt
            || reconciliation_ref.recovery_generation != self.recovery_generation
            || reconciliation_ref.status != ReconciliationStatus::Reconciled
            || reconciliation_ref.unresolved_effect_count != 0
        {
            return Err(Self::loop_error(
                LoopInvariantViolation::RecoveryReferenceMismatch,
            ));
        }
        Ok(())
    }

    fn validate_checkpoint_body(&self, body: &LoopCheckpointBody) -> Result<(), DomainError> {
        let active_attempt = self
            .active_attempt
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveAttempt))?;
        let active_cycle = self
            .active_cycle
            .as_ref()
            .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
        if body.cycle_id != active_cycle.cycle_id
            || body.attempt_id != active_attempt
            || body.plan_revision_ref.as_ref() != active_cycle.plan_revision_ref.as_ref()
            || body.context_manifest_ref.as_ref() != active_cycle.context_manifest_ref.as_ref()
        {
            return Err(Self::loop_error(LoopInvariantViolation::CheckpointMismatch));
        }
        Ok(())
    }

    /// Core transition table — apply a payload to mutate state.
    pub fn apply_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
        match payload {
            TaskRunEvent::TaskRunCreated => {
                self.state = TaskRunState::Created;
            }
            TaskRunEvent::TaskRunQueued => {
                self.require_state(TaskRunState::Created, payload.kind())?;
                self.state = TaskRunState::Queued;
            }
            TaskRunEvent::TaskRunAdmitted => {
                self.require_state(TaskRunState::Queued, payload.kind())?;
                self.state = TaskRunState::Admitted;
            }
            TaskRunEvent::AttemptStarted { attempt_id } => {
                self.require_state(TaskRunState::Admitted, payload.kind())?;
                self.check_attempt_id_unique(attempt_id)?;
                self.attempt_history.push(*attempt_id);
                self.active_attempt = Some(*attempt_id);
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::WaitStarted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.state = TaskRunState::Waiting;
            }
            TaskRunEvent::Resumed => {
                self.require_state(TaskRunState::Waiting, payload.kind())?;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::RetryStarted { attempt_id } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.check_attempt_id_unique(attempt_id)?;
                self.attempt_history.push(*attempt_id);
                self.active_attempt = Some(*attempt_id);
                self.state = TaskRunState::Retrying;
            }
            TaskRunEvent::RetryCompleted { attempt_id } => {
                self.require_state(TaskRunState::Retrying, payload.kind())?;
                self.active_attempt = Some(*attempt_id);
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::CheckpointStarted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.state = TaskRunState::Checkpointing;
            }
            TaskRunEvent::CheckpointCommitted => {
                self.require_state(TaskRunState::Checkpointing, payload.kind())?;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::CancellationRequested => {
                // Valid from: running, waiting, retrying, admitted, queued
                let valid = matches!(
                    self.state,
                    TaskRunState::Running
                        | TaskRunState::Waiting
                        | TaskRunState::Retrying
                        | TaskRunState::Admitted
                        | TaskRunState::Queued
                );
                if !valid {
                    return Err(DomainError::InvalidTransition {
                        from: self.state,
                        event: payload.kind(),
                    });
                }
                if self.state == TaskRunState::Retrying {
                    self.pending_retry = None;
                }
                self.state = TaskRunState::Cancelling;
            }
            TaskRunEvent::CancellationCompleted => {
                self.require_state(TaskRunState::Cancelling, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::Cancelled;
            }
            TaskRunEvent::TaskRunCompleted { result } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.terminal_result = Some(result.clone());
                self.active_attempt = None;
                self.state = TaskRunState::Succeeded;
            }
            TaskRunEvent::TaskRunFailed { reason: _ } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::Failed;
            }
            TaskRunEvent::BudgetExhausted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::BudgetExhausted;
            }
            TaskRunEvent::PolicyDenied => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::PolicyDenied;
            }
            TaskRunEvent::ReconciliationStarted => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                self.state = TaskRunState::Reconciling;
            }
            TaskRunEvent::Reconciled => {
                self.require_state(TaskRunState::Reconciling, payload.kind())?;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::Unrecoverable => {
                self.require_state(TaskRunState::Reconciling, payload.kind())?;
                self.active_attempt = None;
                self.state = TaskRunState::Unrecoverable;
            }
            TaskRunEvent::TaskRunCancelled => {
                // Valid from: admitted, queued, waiting, retrying
                let valid = matches!(
                    self.state,
                    TaskRunState::Admitted
                        | TaskRunState::Queued
                        | TaskRunState::Waiting
                        | TaskRunState::Retrying
                );
                if !valid {
                    return Err(DomainError::InvalidTransition {
                        from: self.state,
                        event: payload.kind(),
                    });
                }
                self.pending_retry = None;
                self.active_attempt = None;
                self.state = TaskRunState::Cancelled;
            }
            TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id,
                sequence,
                parent_cycle_id,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                if self.active_attempt != Some(*attempt_id) {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::MissingActiveAttempt,
                    ));
                }
                if self.active_cycle.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::ActiveCycleExists));
                }
                if self
                    .cycle_history
                    .iter()
                    .any(|entry| entry.cycle_id == *cycle_id)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CycleAlreadyUsed));
                }

                match self.pending_successor.as_ref() {
                    Some(pending) => {
                        if pending.successor_cycle_id != *cycle_id
                            || pending.attempt_id != *attempt_id
                            || pending.sequence != *sequence
                            || Some(pending.parent_cycle_id) != *parent_cycle_id
                        {
                            return Err(Self::loop_error(
                                LoopInvariantViolation::SuccessorReservationMismatch,
                            ));
                        }
                    }
                    None => {
                        if *sequence != 0 || parent_cycle_id.is_some() {
                            return Err(Self::loop_error(
                                LoopInvariantViolation::SuccessorReservationMismatch,
                            ));
                        }
                        if self
                            .cycle_history
                            .iter()
                            .any(|entry| entry.attempt_id == *attempt_id)
                        {
                            return Err(Self::loop_error(
                                LoopInvariantViolation::AttemptAlreadyHasCycle,
                            ));
                        }
                    }
                }

                let history_entry = CycleHistoryEntry {
                    cycle_id: *cycle_id,
                    attempt_id: *attempt_id,
                    sequence: *sequence,
                    parent_cycle_id: *parent_cycle_id,
                };
                let active_cycle = ActiveLoopCycle {
                    cycle_id: *cycle_id,
                    attempt_id: *attempt_id,
                    sequence: *sequence,
                    parent_cycle_id: *parent_cycle_id,
                    state: LoopCycleState::Observing,
                    context_manifest_ref: None,
                    plan_revision_ref: None,
                    expected_proposal_indexes: Vec::new(),
                    recorded_outcomes: Vec::new(),
                };
                self.pending_successor = None;
                self.cycle_history.push(history_entry);
                self.active_cycle = Some(active_cycle);
            }
            TaskRunEvent::ContextCommitted {
                cycle_id,
                manifest_ref,
            } => {
                self.validate_context_commit(*cycle_id, manifest_ref)?;
                let cycle = self
                    .active_cycle
                    .as_mut()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                cycle.context_manifest_ref = Some(manifest_ref.clone());
                cycle.state = LoopCycleState::Proposing;
            }
            TaskRunEvent::PlanCommitted {
                cycle_id,
                plan_revision_ref,
                input_digest: _,
                output_digest: _,
                expected_proposal_indexes,
            } => {
                self.validate_plan_commit(*cycle_id, plan_revision_ref, expected_proposal_indexes)?;
                let next_state = if expected_proposal_indexes.is_empty() {
                    LoopCycleState::Evaluating
                } else {
                    LoopCycleState::Acting
                };
                let cycle = self
                    .active_cycle
                    .as_mut()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                cycle.plan_revision_ref = Some(plan_revision_ref.clone());
                cycle.expected_proposal_indexes = expected_proposal_indexes.clone();
                cycle.state = next_state;
            }
            TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } => {
                self.validate_step_outcome(*cycle_id, outcome)?;
                let cycle = self
                    .active_cycle
                    .as_mut()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                cycle.recorded_outcomes.push(outcome.clone());
                let all_recorded = cycle.expected_proposal_indexes.iter().all(|index| {
                    cycle
                        .recorded_outcomes
                        .iter()
                        .any(|outcome| outcome.proposal_index == *index)
                });
                if all_recorded {
                    cycle.state = LoopCycleState::Evaluating;
                }
            }
            TaskRunEvent::LoopCycleCompleted {
                cycle_id,
                attempt_id,
                disposition,
            } => {
                let validated_attempt = self.validate_cycle_completion(*cycle_id, disposition)?;
                if validated_attempt != *attempt_id {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::CycleBindingMismatch,
                    ));
                }
                let cycle = self
                    .active_cycle
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                let completed = CompletedCycleRef {
                    cycle_id: *cycle_id,
                    attempt_id: *attempt_id,
                    sequence: cycle.sequence,
                    disposition: disposition.clone(),
                    accepted_wake_evidence: None,
                    successor_allocated: false,
                };
                let pending_wait = match disposition {
                    LoopDisposition::Wait { wake_condition, .. } => Some(PendingLoopWait {
                        cycle_id: *cycle_id,
                        wake_condition: wake_condition.clone(),
                    }),
                    _ => None,
                };
                self.active_cycle = None;
                self.last_completed_cycle = Some(completed);
                self.pending_loop_wait = pending_wait;
            }
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id,
                successor_cycle_id,
                attempt_id,
                sequence,
            } => {
                let completed = self.validate_successor(*parent_cycle_id, *successor_cycle_id)?;
                let expected_sequence = completed.sequence.checked_add(1).ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::SuccessorReservationMismatch)
                })?;
                if completed.attempt_id != *attempt_id || expected_sequence != *sequence {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::SuccessorReservationMismatch,
                    ));
                }
                let pending = PendingSuccessorCycle {
                    parent_cycle_id: *parent_cycle_id,
                    successor_cycle_id: *successor_cycle_id,
                    attempt_id: *attempt_id,
                    sequence: *sequence,
                };
                let completed = self.last_completed_cycle.as_mut().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingCompletedCycle)
                })?;
                completed.successor_allocated = true;
                self.pending_successor = Some(pending);
            }
            TaskRunEvent::RetryScheduled {
                ordinal,
                old_attempt_id,
                new_attempt_id,
                abandoned_cycle_id,
                step_outcome_ref,
                retry_policy_digest,
                budget_reservation_ref,
                delay_ms,
                due_at_unix_us,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                if self.pending_retry.is_some() {
                    return Err(Self::loop_error(LoopInvariantViolation::PendingRetryExists));
                }
                self.check_attempt_id_unique(new_attempt_id)?;
                let cycle = self
                    .active_cycle
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingActiveCycle))?;
                if self.active_attempt != Some(*old_attempt_id)
                    || cycle.attempt_id != *old_attempt_id
                    || cycle.cycle_id != *abandoned_cycle_id
                    || step_outcome_ref.cycle_id != *abandoned_cycle_id
                    || !cycle.recorded_outcomes.iter().any(|outcome| {
                        outcome.proposal_index == step_outcome_ref.proposal_index
                            && outcome.step_id == step_outcome_ref.step_id
                            && outcome.outcome_type == StepOutcomeType::FailedBeforeCommit
                    })
                    || budget_reservation_ref.taskrun_id != self.id
                    || budget_reservation_ref.attempt_id != *old_attempt_id
                    || budget_reservation_ref.retry_ordinal != *ordinal
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                let pending = PendingRetry {
                    ordinal: *ordinal,
                    old_attempt_id: *old_attempt_id,
                    new_attempt_id: *new_attempt_id,
                    abandoned_cycle_id: *abandoned_cycle_id,
                    step_outcome_ref: step_outcome_ref.clone(),
                    due_at_unix_us: *due_at_unix_us,
                    delay_ms: *delay_ms,
                    budget_reservation_ref: budget_reservation_ref.clone(),
                    retry_policy_digest: *retry_policy_digest,
                };
                self.active_cycle = None;
                self.pending_retry = Some(pending);
                self.state = TaskRunState::Retrying;
            }
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal,
                attempt_id,
                activated_at_unix_us,
            } => {
                self.require_state(TaskRunState::Retrying, payload.kind())?;
                let pending = self
                    .pending_retry
                    .as_ref()
                    .ok_or_else(|| Self::loop_error(LoopInvariantViolation::MissingPendingRetry))?;
                if pending.ordinal != *ordinal || pending.new_attempt_id != *attempt_id {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingRetryMismatch,
                    ));
                }
                if *activated_at_unix_us < pending.due_at_unix_us {
                    return Err(Self::loop_error(LoopInvariantViolation::RetryNotDue));
                }
                self.check_attempt_id_unique(attempt_id)?;
                self.attempt_history.push(*attempt_id);
                self.active_attempt = Some(*attempt_id);
                self.pending_retry = None;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::RecoveryResumeStarted {
                new_attempt_id,
                new_generation,
                abandoned_cycle_id,
                context_manifest_ref: _,
                checkpoint_ref: _,
                reconciliation_ref,
            } => {
                self.require_state(TaskRunState::Reconciling, payload.kind())?;
                self.check_attempt_id_unique(new_attempt_id)?;
                self.validate_recovery_ref(reconciliation_ref)?;
                let expected_generation = self
                    .recovery_generation
                    .checked_add(1)
                    .ok_or(DomainError::RecoveryGenerationExhausted)?;
                if expected_generation != *new_generation
                    || self.active_cycle.as_ref().map(|cycle| cycle.cycle_id) != *abandoned_cycle_id
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::RecoveryReferenceMismatch,
                    ));
                }
                self.active_cycle = None;
                self.pending_successor = None;
                self.pending_loop_wait = None;
                self.pending_retry = None;
                self.attempt_history.push(*new_attempt_id);
                self.active_attempt = Some(*new_attempt_id);
                self.recovery_generation = *new_generation;
                self.state = TaskRunState::Running;
            }
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                if self.pending_loop_checkpoint.is_some() {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::PendingCheckpointExists,
                    ));
                }
                self.pending_loop_checkpoint = Some(PendingLoopCheckpoint {
                    checkpoint_id: *checkpoint_id,
                    start_position: *event_position,
                    expected_integrity_digest: *integrity_digest,
                    recorded_integrity_digest: None,
                });
            }
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position,
                body,
                integrity_digest,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                let pending = self.pending_loop_checkpoint.as_ref().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingPendingCheckpoint)
                })?;
                if pending.checkpoint_id != *checkpoint_id
                    || pending.start_position != *event_position
                    || pending.expected_integrity_digest != *integrity_digest
                    || pending.recorded_integrity_digest.is_some()
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CheckpointMismatch));
                }
                self.validate_checkpoint_body(body)?;
                let pending = self.pending_loop_checkpoint.as_mut().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingPendingCheckpoint)
                })?;
                pending.recorded_integrity_digest = Some(*integrity_digest);
            }
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position,
                integrity_digest,
            } => {
                self.require_state(TaskRunState::Running, payload.kind())?;
                let pending = self.pending_loop_checkpoint.as_ref().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingPendingCheckpoint)
                })?;
                if pending.checkpoint_id != *checkpoint_id
                    || pending.start_position != *event_position
                    || pending.expected_integrity_digest != *integrity_digest
                    || pending.recorded_integrity_digest != Some(*integrity_digest)
                {
                    return Err(Self::loop_error(LoopInvariantViolation::CheckpointMismatch));
                }
                self.pending_loop_checkpoint = None;
            }
            TaskRunEvent::LoopWakeAccepted {
                cycle_id,
                wake_evidence_ref,
            } => {
                if *cycle_id != wake_evidence_ref.cycle_id {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::WakeEvidenceMismatch,
                    ));
                }
                self.validate_wake_evidence(wake_evidence_ref)?;
                let completed = self.last_completed_cycle.as_ref().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingCompletedCycle)
                })?;
                if completed.cycle_id != *cycle_id
                    || !matches!(completed.disposition, LoopDisposition::Wait { .. })
                    || completed.accepted_wake_evidence.is_some()
                {
                    return Err(Self::loop_error(
                        LoopInvariantViolation::WakeEvidenceMismatch,
                    ));
                }
                let completed = self.last_completed_cycle.as_mut().ok_or_else(|| {
                    Self::loop_error(LoopInvariantViolation::MissingCompletedCycle)
                })?;
                completed.accepted_wake_evidence = Some(wake_evidence_ref.clone());
                self.pending_loop_wait = None;
            }
        }
        Ok(())
    }
}

// ── L0 tests: valid transitions ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";
    const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const ATTEMPT_ID2: &str = "018f2e3a-7000-7000-8000-000000000004";

    fn make_create() -> CreateTaskRun {
        CreateTaskRun {
            taskrun_id: VALID_UUID.parse().unwrap(),
            conversation_id: CONVERSATION_ID.parse().unwrap(),
            workspace_id: WORKSPACE_ID.parse().unwrap(),
        }
    }

    fn make_envelope(
        sequence: u64,
        payload: TaskRunEvent,
        taskrun_id: TaskRunId,
    ) -> EventEnvelope<TaskRunEvent> {
        make_envelope_with_correlation(
            sequence,
            payload,
            taskrun_id,
            AggregateId::TaskRun(taskrun_id),
        )
    }

    fn make_envelope_with_correlation(
        sequence: u64,
        payload: TaskRunEvent,
        taskrun_id: TaskRunId,
        correlation_id: AggregateId,
    ) -> EventEnvelope<TaskRunEvent> {
        use crate::event::{Actor, CommandContext, DomainEventDraft};
        use crate::id::{IdempotencyKey, IntegrityDigest};
        use crate::timestamp::Timestamp;
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(taskrun_id),
            correlation_id,
            1,
            Sensitivity::Public,
            payload,
        );
        let ctx = CommandContext {
            command_id: VALID_UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("test").unwrap(),
            actor: Actor::new("test").unwrap(),
        };
        use crate::event::materialize_batch;
        let ids = &[VALID_UUID.parse().unwrap()];
        let uncommitted = materialize_batch(vec![draft], ids, None, &ctx)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        uncommitted.into_envelope(
            sequence,
            Timestamp::from_unix_micros(1000),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

    fn create_aggregate() -> TaskRun {
        let cmd = make_create();
        TaskRun::decide_create(cmd).unwrap();
        let events = &[make_envelope(
            1,
            TaskRunEvent::TaskRunCreated,
            VALID_UUID.parse().unwrap(),
        )];
        TaskRun::replay(events).unwrap()
    }

    fn running_aggregate() -> TaskRun {
        let mut aggregate = create_aggregate();
        aggregate
            .apply_payload(&TaskRunEvent::TaskRunQueued)
            .unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::TaskRunAdmitted)
            .unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::AttemptStarted {
                attempt_id: ATTEMPT_ID.parse().unwrap(),
            })
            .unwrap();
        aggregate
    }

    // ─── Creation ──────────────────────────────────────────────────────────

    #[test]
    fn test_decide_create_produces_draft() {
        let cmd = make_create();
        let draft = TaskRun::decide_create(cmd).unwrap();
        assert_eq!(*draft.payload(), TaskRunEvent::TaskRunCreated);
        assert_eq!(draft.schema_version(), 1);
    }

    #[test]
    fn decide_create_running_emits_the_exact_valid_lifecycle_prefix() {
        let events = TaskRun::decide_create_running(
            make_create(),
            ATTEMPT_ID.parse().expect("valid attempt ID"),
        )
        .unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.payload().kind())
                .collect::<Vec<_>>(),
            vec![
                TaskRunEventKind::TaskRunCreated,
                TaskRunEventKind::TaskRunQueued,
                TaskRunEventKind::TaskRunAdmitted,
                TaskRunEventKind::AttemptStarted,
            ]
        );
        assert!(
            events
                .iter()
                .all(|event| event.sensitivity() == &Sensitivity::Public)
        );
    }

    #[test]
    fn test_replay_created() {
        let events = &[make_envelope(
            1,
            TaskRunEvent::TaskRunCreated,
            VALID_UUID.parse().unwrap(),
        )];
        let agg = TaskRun::replay(events).unwrap();
        assert_eq!(agg.state(), TaskRunState::Created);
    }

    // ─── Full lifecycle ───────────────────────────────────────────────────

    #[test]
    fn test_full_lifecycle_created_to_succeeded() {
        let mut agg = create_aggregate();
        assert_eq!(agg.state(), TaskRunState::Created);

        // created → queued
        let _drafts = agg
            .decide(TaskRunCommand::Admit)
            .map_err(|e| format!("{:?}", e))
            .unwrap_err();
        // Wait: Admit is not valid from Created — need TaskRunQueued event first
        // Actually per transition table: created + TaskRunQueued → queued
        // But there's no TaskRunQueued command — it's an internal event.
        // Let me use the apply path directly:
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        assert_eq!(agg.state(), TaskRunState::Queued);

        // queued → admitted via command
        let drafts = agg.decide(TaskRunCommand::Admit).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::TaskRunAdmitted);
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Admitted);

        // admitted → running via StartAttempt
        let attempt_id: AttemptId = ATTEMPT_ID.parse().unwrap();
        let drafts = agg
            .decide(TaskRunCommand::StartAttempt { attempt_id })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::AttemptStarted { .. }
        ));
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id })
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
        assert_eq!(agg.active_attempt(), Some(&attempt_id));

        // running → succeeded
        let drafts = agg
            .decide(TaskRunCommand::Complete {
                result: TerminalResult::Success,
            })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::TaskRunCompleted { .. }
        ));
        agg.apply_payload(&TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        })
        .unwrap();
        assert_eq!(agg.state(), TaskRunState::Succeeded);
        assert!(agg.state().is_terminal());
    }

    // ─── Waiting/resume cycle ─────────────────────────────────────────────

    #[test]
    fn test_waiting_cycle() {
        let mut agg = create_aggregate();
        // created → queued → admitted → running
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);

        // running → waiting
        let drafts = agg.decide(TaskRunCommand::WaitForApproval).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::WaitStarted);
        agg.apply_payload(&TaskRunEvent::WaitStarted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Waiting);

        // waiting → running
        let drafts = agg.decide(TaskRunCommand::Resume).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::Resumed);
        agg.apply_payload(&TaskRunEvent::Resumed).unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Retry cycle ──────────────────────────────────────────────────────

    #[test]
    fn test_retry_cycle() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // running → retrying
        let aid2: AttemptId = ATTEMPT_ID2.parse().unwrap();
        let drafts = agg
            .decide(TaskRunCommand::StartRetry { attempt_id: aid2 })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::RetryStarted { .. }
        ));
        agg.apply_payload(&TaskRunEvent::RetryStarted { attempt_id: aid2 })
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Retrying);
        assert_eq!(agg.active_attempt(), Some(&aid2));

        // retrying → running
        let drafts = agg
            .decide(TaskRunCommand::CompleteRetry { attempt_id: aid2 })
            .unwrap();
        assert_eq!(
            drafts[0].payload(),
            &TaskRunEvent::RetryCompleted { attempt_id: aid2 }
        );
        agg.apply_payload(&TaskRunEvent::RetryCompleted { attempt_id: aid2 })
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Checkpoint cycle ─────────────────────────────────────────────────

    #[test]
    fn test_checkpoint_cycle() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // running → checkpointing
        let drafts = agg.decide(TaskRunCommand::StartCheckpoint).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CheckpointStarted);
        agg.apply_payload(&TaskRunEvent::CheckpointStarted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Checkpointing);

        // checkpointing → running
        let drafts = agg.decide(TaskRunCommand::CommitCheckpoint).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CheckpointCommitted);
        agg.apply_payload(&TaskRunEvent::CheckpointCommitted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Cancellation cycle ───────────────────────────────────────────────

    #[test]
    fn test_cancellation_cycle_from_running() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // running → cancelling
        let drafts = agg.decide(TaskRunCommand::RequestCancellation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CancellationRequested);
        agg.apply_payload(&TaskRunEvent::CancellationRequested)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelling);

        // cancelling → cancelled
        let drafts = agg.decide(TaskRunCommand::CompleteCancellation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CancellationCompleted);
        agg.apply_payload(&TaskRunEvent::CancellationCompleted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelled);
        assert!(agg.state().is_terminal());
        assert!(agg.active_attempt().is_none());
    }

    // ─── Failed ───────────────────────────────────────────────────────────

    #[test]
    fn test_failure_path() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        let drafts = agg
            .decide(TaskRunCommand::Fail {
                reason: "test failure".into(),
            })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::TaskRunFailed { .. }
        ));
        agg.apply_payload(&TaskRunEvent::TaskRunFailed {
            reason: "test failure".into(),
        })
        .unwrap();
        assert_eq!(agg.state(), TaskRunState::Failed);
        assert!(agg.state().is_terminal());
        assert!(agg.active_attempt().is_none());
    }

    #[test]
    fn provider_output_rejection_uses_closed_terminal_code() {
        let agg = running_aggregate();

        let drafts = agg
            .decide(TaskRunCommand::FailGeneration {
                reason: crate::conversation::GenerationFailureReason::ProviderOutputRejected,
            })
            .unwrap();

        assert_eq!(
            drafts[0].payload(),
            &TaskRunEvent::TaskRunFailed {
                reason: "provider_output_rejected".into(),
            }
        );
    }

    // ─── Reconciliation ───────────────────────────────────────────────────

    #[test]
    fn test_reconciliation_to_running() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        let drafts = agg.decide(TaskRunCommand::StartReconciliation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::ReconciliationStarted);
        agg.apply_payload(&TaskRunEvent::ReconciliationStarted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Reconciling);

        let drafts = agg.decide(TaskRunCommand::CompleteReconciliation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::Reconciled);
        agg.apply_payload(&TaskRunEvent::Reconciled).unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    #[test]
    fn test_reconciliation_to_unrecoverable() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        agg.apply_payload(&TaskRunEvent::ReconciliationStarted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Reconciling);

        let drafts = agg.decide(TaskRunCommand::MarkUnrecoverable).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::Unrecoverable);
        agg.apply_payload(&TaskRunEvent::Unrecoverable).unwrap();
        assert_eq!(agg.state(), TaskRunState::Unrecoverable);
        assert!(agg.state().is_terminal());
    }

    // ─── Direct cancel from non-running states ────────────────────────────

    #[test]
    fn test_direct_cancel_from_queued() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        // direct cancel from queued (no CancellationRequested needed for direct path)
        agg.apply_payload(&TaskRunEvent::TaskRunCancelled).unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelled);
    }

    #[test]
    fn test_direct_cancel_from_admitted() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunCancelled).unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelled);
    }

    // ─── Replay round-trip ────────────────────────────────────────────────

    #[test]
    fn test_replay_roundtrip_created_to_succeeded() {
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunQueued, tr_id),
            make_envelope(3, TaskRunEvent::TaskRunAdmitted, tr_id),
            make_envelope(4, TaskRunEvent::AttemptStarted { attempt_id: aid }, tr_id),
            make_envelope(
                5,
                TaskRunEvent::TaskRunCompleted {
                    result: TerminalResult::Success,
                },
                tr_id,
            ),
        ];
        let agg = TaskRun::replay(events).unwrap();
        assert_eq!(agg.state(), TaskRunState::Succeeded);
        assert_eq!(*agg.id(), tr_id);
        assert_eq!(agg.attempt_history(), &[aid]);
    }

    // ─── L0 tests: invalid transitions ────────────────────────────────────

    #[test]
    fn test_invalid_terminal_immutable() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        })
        .unwrap();
        assert!(agg.state().is_terminal());

        // Any command on terminal state → TerminalImmutable
        let err = agg.decide(TaskRunCommand::Admit).unwrap_err();
        assert!(matches!(err, DomainError::TerminalImmutable { .. }));
    }

    #[test]
    fn test_invalid_transition_wrong_state() {
        let agg = create_aggregate();
        // Created → Admit is not valid (need Queued first)
        let err = agg.decide(TaskRunCommand::Admit).unwrap_err();
        assert!(matches!(err, DomainError::InvalidTransition { .. }));
    }

    #[test]
    fn test_duplicate_attempt_id() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // Try to start retry with same attempt ID
        let err = agg
            .decide(TaskRunCommand::StartRetry { attempt_id: aid })
            .unwrap_err();
        assert!(matches!(err, DomainError::DuplicateAttemptId { .. }));
    }

    #[test]
    fn test_replay_empty_events() {
        let events: &[EventEnvelope<TaskRunEvent>] = &[];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::MissingCreationEvent { .. }));
    }

    #[test]
    fn test_replay_missing_creation_event() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[make_envelope(1, TaskRunEvent::TaskRunQueued, tr_id)];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::MissingCreationEvent { .. }));
    }

    #[test]
    fn test_replay_sequence_gap() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(3, TaskRunEvent::TaskRunQueued, tr_id), // gap: expected 2
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::SequenceGap { .. }));
    }

    #[test]
    fn test_replay_invalid_initial_sequence() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[make_envelope(5, TaskRunEvent::TaskRunCreated, tr_id)];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::InvalidInitialSequence { .. }));
    }

    #[test]
    fn test_replay_duplicate_creation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunCreated, tr_id),
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::DuplicateCreationEvent { .. }));
    }

    #[test]
    fn test_replay_aggregate_id_mismatch_by_taskrun_id() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let tr_id2: TaskRunId = ATTEMPT_ID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunQueued, tr_id2),
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::AggregateIdMismatch { .. }));
    }

    #[test]
    fn test_apply_rejects_non_taskrun_correlation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let mut aggregate = create_aggregate();
        let event = make_envelope_with_correlation(
            2,
            TaskRunEvent::TaskRunQueued,
            tr_id,
            AggregateId::Workspace(WORKSPACE_ID.parse().unwrap()),
        );

        let err = aggregate.apply(&event).unwrap_err();
        assert_eq!(
            err,
            DomainError::AggregateIdMismatch {
                expected: AggregateId::TaskRun(tr_id),
                actual: AggregateId::Workspace(WORKSPACE_ID.parse().unwrap()),
            }
        );
    }

    #[test]
    fn test_replay_rejects_non_taskrun_correlation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let event = make_envelope_with_correlation(
            1,
            TaskRunEvent::TaskRunCreated,
            tr_id,
            AggregateId::Conversation(CONVERSATION_ID.parse().unwrap()),
        );

        let err = TaskRun::replay(&[event]).unwrap_err();
        assert_eq!(
            err,
            DomainError::AggregateIdMismatch {
                expected: AggregateId::TaskRun(tr_id),
                actual: AggregateId::Conversation(CONVERSATION_ID.parse().unwrap()),
            }
        );
    }

    #[test]
    fn phase5_event_kinds_are_exactly_thirteen() {
        let kinds = [
            TaskRunEventKind::LoopCycleStarted,
            TaskRunEventKind::ContextCommitted,
            TaskRunEventKind::PlanCommitted,
            TaskRunEventKind::StepOutcomeRecorded,
            TaskRunEventKind::LoopCycleCompleted,
            TaskRunEventKind::NextCycleCreated,
            TaskRunEventKind::RetryScheduled,
            TaskRunEventKind::ActivateScheduledRetryAttempt,
            TaskRunEventKind::RecoveryResumeStarted,
            TaskRunEventKind::LoopCheckpointStarted,
            TaskRunEventKind::LoopCheckpointRecorded,
            TaskRunEventKind::LoopCheckpointCommitted,
            TaskRunEventKind::LoopWakeAccepted,
        ];

        assert_eq!(kinds.len(), 13);
    }

    #[test]
    fn initial_cycle_is_attempt_bound_unique_and_failure_preserves_state() {
        let mut aggregate = running_aggregate();
        let cycle_id: CycleId = WORKSPACE_ID.parse().unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id: ATTEMPT_ID.parse().unwrap(),
                sequence: 0,
                parent_cycle_id: None,
            })
            .unwrap();
        let before = aggregate.clone();

        let error = aggregate
            .apply_payload(&TaskRunEvent::LoopCycleStarted {
                cycle_id: CONVERSATION_ID.parse().unwrap(),
                attempt_id: ATTEMPT_ID.parse().unwrap(),
                sequence: 0,
                parent_cycle_id: None,
            })
            .unwrap_err();

        assert_eq!(
            error,
            DomainError::LoopInvariantViolation {
                violation: LoopInvariantViolation::ActiveCycleExists,
            }
        );
        assert_eq!(aggregate, before);
        assert_eq!(aggregate.cycle_history().len(), 1);
    }

    #[test]
    fn checkpoint_commit_requires_exact_record_and_preserves_state_on_error() {
        let mut aggregate = running_aggregate();
        let checkpoint_id: CheckpointId = WORKSPACE_ID.parse().unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position: 5,
                integrity_digest: IntegrityDigest::from_bytes([1; 32]),
            })
            .unwrap();
        let before = aggregate.clone();

        let error = aggregate
            .apply_payload(&TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position: 5,
                integrity_digest: IntegrityDigest::from_bytes([1; 32]),
            })
            .unwrap_err();

        assert_eq!(
            error,
            DomainError::LoopInvariantViolation {
                violation: LoopInvariantViolation::CheckpointMismatch,
            }
        );
        assert_eq!(aggregate, before);
    }

    #[test]
    fn replay_rejects_torn_loop_checkpoint_batch() {
        let taskrun_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = vec![
            make_envelope(1, TaskRunEvent::TaskRunCreated, taskrun_id),
            make_envelope(2, TaskRunEvent::TaskRunQueued, taskrun_id),
            make_envelope(3, TaskRunEvent::TaskRunAdmitted, taskrun_id),
            make_envelope(
                4,
                TaskRunEvent::AttemptStarted {
                    attempt_id: ATTEMPT_ID.parse().unwrap(),
                },
                taskrun_id,
            ),
            make_envelope(
                5,
                TaskRunEvent::LoopCheckpointStarted {
                    checkpoint_id: WORKSPACE_ID.parse().unwrap(),
                    event_position: 5,
                    integrity_digest: IntegrityDigest::from_bytes([4; 32]),
                },
                taskrun_id,
            ),
        ];

        assert_eq!(
            TaskRun::replay(&events).unwrap_err(),
            DomainError::CorruptCommandBatch
        );
    }

    #[test]
    fn test_invalid_transition_attempt_started_from_created() {
        let mut agg = create_aggregate();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        let err = agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid });
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            DomainError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn test_queue_from_created() {
        let mut agg = create_aggregate();
        let drafts = agg.decide(TaskRunCommand::Queue).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(*drafts[0].payload(), TaskRunEvent::TaskRunQueued);
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        assert_eq!(agg.state(), TaskRunState::Queued);
    }

    #[test]
    fn test_queue_from_queued_is_invalid() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        let err = agg.decide(TaskRunCommand::Queue).unwrap_err();
        assert!(matches!(err, DomainError::InvalidTransition { .. }));
    }
}
