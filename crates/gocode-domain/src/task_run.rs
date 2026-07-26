//! TaskRun aggregate — lifecycle state machine, events, transition table.
//!
//! The TaskRun is the core aggregate: it tracks execution state,
//! attempt history, and terminal outcomes.

use crate::command::{CreateTaskRun, TaskRunCommand, TerminalResult};
use crate::error::DomainError;
use crate::event::{AggregateType, DomainEventDraft, EventEnvelope, Sensitivity};
use crate::id::{AggregateId, AttemptId, TaskRunId};

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

    // ── decide_create ────────────────────────────────────────────────────

    /// Handle a [`CreateTaskRun`] command — produces the initial event.
    ///
    /// Assumes the aggregate does not exist yet.
    pub fn decide_create(
        command: CreateTaskRun,
    ) -> Result<DomainEventDraft<TaskRunEvent>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(command.taskrun_id);
        Ok(DomainEventDraft::new(
            aggregate_id,
            command.taskrun_id,
            1,
            Sensitivity::Public,
            TaskRunEvent::TaskRunCreated,
        ))
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
            DomainEventDraft::new(aggregate_id, self.id, 1, sensitivity, payload)
        };

        match command {
            TaskRunCommand::Admit => {
                self.require_state(TaskRunState::Queued, TaskRunEventKind::TaskRunAdmitted)?;
                Ok(vec![draft(TaskRunEvent::TaskRunAdmitted, Sensitivity::Public)])
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
                Ok(vec![draft(
                    TaskRunEvent::RetryCompleted { attempt_id },
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::StartCheckpoint => {
                self.require_state(
                    TaskRunState::Running,
                    TaskRunEventKind::CheckpointStarted,
                )?;
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
                self.require_state(
                    TaskRunState::Running,
                    TaskRunEventKind::TaskRunCompleted,
                )?;
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
                self.require_state(
                    TaskRunState::Reconciling,
                    TaskRunEventKind::Reconciled,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::Reconciled,
                    Sensitivity::Public,
                )])
            }
            TaskRunCommand::MarkUnrecoverable => {
                self.require_state(
                    TaskRunState::Reconciling,
                    TaskRunEventKind::Unrecoverable,
                )?;
                Ok(vec![draft(
                    TaskRunEvent::Unrecoverable,
                    Sensitivity::Public,
                )])
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
                expected,
                actual: event.aggregate_id().clone(),
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
    pub fn replay(
        events: &[EventEnvelope<TaskRunEvent>],
    ) -> Result<Self, DomainError> {
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

        // Validate taskrun_id consistency and build initial aggregate
        let taskrun_id = first.taskrun_id();
        let mut agg = Self {
            id: *taskrun_id,
            state: TaskRunState::Created,
            active_attempt: None,
            attempt_history: Vec::new(),
            terminal_result: None,
        };

        let mut creation_seen = false;
        for (expected_seq, event) in (1u64..).zip(events) {
            // Sequence continuity
            if event.sequence() != expected_seq {
                return Err(DomainError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence(),
                });
            }

            // All events must share the same taskrun_id
            if *event.taskrun_id() != *taskrun_id {
                return Err(DomainError::AggregateIdMismatch {
                    expected: AggregateId::TaskRun(*taskrun_id),
                    actual: event.aggregate_id().clone(),
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

            agg.apply_payload(payload)?;
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

    /// Core transition table — apply a payload to mutate state.
    fn apply_payload(&mut self, payload: &TaskRunEvent) -> Result<(), DomainError> {
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
                self.active_attempt = None;
                self.state = TaskRunState::Cancelled;
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

    fn make_envelope(sequence: u64, payload: TaskRunEvent, taskrun_id: TaskRunId) -> EventEnvelope<TaskRunEvent> {
        use crate::timestamp::Timestamp;
        use crate::id::{IntegrityDigest, IdempotencyKey};
        use crate::event::{Actor, CommandContext, DomainEventDraft};
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(taskrun_id),
            taskrun_id,
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

    // ─── Creation ──────────────────────────────────────────────────────────

    #[test]
    fn test_decide_create_produces_draft() {
        let cmd = make_create();
        let draft = TaskRun::decide_create(cmd).unwrap();
        assert_eq!(*draft.payload(), TaskRunEvent::TaskRunCreated);
        assert_eq!(draft.schema_version(), 1);
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
        let drafts = agg.decide(TaskRunCommand::Admit).map_err(|e| format!("{:?}", e)).unwrap_err();
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id }).unwrap();
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();

        // running → retrying
        let aid2: AttemptId = ATTEMPT_ID2.parse().unwrap();
        let drafts = agg
            .decide(TaskRunCommand::StartRetry { attempt_id: aid2 })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::RetryStarted { .. }
        ));
        agg.apply_payload(&TaskRunEvent::RetryStarted { attempt_id: aid2 }).unwrap();
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
        agg.apply_payload(&TaskRunEvent::RetryCompleted { attempt_id: aid2 }).unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Checkpoint cycle ─────────────────────────────────────────────────

    #[test]
    fn test_checkpoint_cycle() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();

        // running → checkpointing
        let drafts = agg.decide(TaskRunCommand::StartCheckpoint).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CheckpointStarted);
        agg.apply_payload(&TaskRunEvent::CheckpointStarted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Checkpointing);

        // checkpointing → running
        let drafts = agg.decide(TaskRunCommand::CommitCheckpoint).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CheckpointCommitted);
        agg.apply_payload(&TaskRunEvent::CheckpointCommitted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Cancellation cycle ───────────────────────────────────────────────

    #[test]
    fn test_cancellation_cycle_from_running() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();

        // running → cancelling
        let drafts = agg.decide(TaskRunCommand::RequestCancellation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CancellationRequested);
        agg.apply_payload(&TaskRunEvent::CancellationRequested).unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelling);

        // cancelling → cancelled
        let drafts = agg.decide(TaskRunCommand::CompleteCancellation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CancellationCompleted);
        agg.apply_payload(&TaskRunEvent::CancellationCompleted).unwrap();
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();

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

    // ─── Reconciliation ───────────────────────────────────────────────────

    #[test]
    fn test_reconciliation_to_running() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();

        let drafts = agg.decide(TaskRunCommand::StartReconciliation).unwrap();
        assert_eq!(
            drafts[0].payload(),
            &TaskRunEvent::ReconciliationStarted
        );
        agg.apply_payload(&TaskRunEvent::ReconciliationStarted).unwrap();
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();
        agg.apply_payload(&TaskRunEvent::ReconciliationStarted).unwrap();
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
            make_envelope(
                4,
                TaskRunEvent::AttemptStarted { attempt_id: aid },
                tr_id,
            ),
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();
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
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid }).unwrap();

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
        let events = &[make_envelope(
            1,
            TaskRunEvent::TaskRunQueued,
            tr_id,
        )];
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
        let events = &[make_envelope(
            5,
            TaskRunEvent::TaskRunCreated,
            tr_id,
        )];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(
            err,
            DomainError::InvalidInitialSequence { .. }
        ));
    }

    #[test]
    fn test_replay_duplicate_creation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunCreated, tr_id),
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(
            err,
            DomainError::DuplicateCreationEvent { .. }
        ));
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
        assert!(matches!(
            err,
            DomainError::AggregateIdMismatch { .. }
        ));
    }

    #[test]
    fn test_invalid_transition_attempt_started_from_created() {
        let mut agg = create_aggregate();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        let err = agg
            .apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid });
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            DomainError::InvalidTransition { .. }
        ));
    }
}
