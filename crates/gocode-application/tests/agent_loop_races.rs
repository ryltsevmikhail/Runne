//! Phase 5 Race Tests — concurrent command protocol at the domain boundary.
//!
use std::cell::{Cell, RefCell};
use std::rc::Rc;

// Each test demonstrates: two mutually exclusive commands are both valid on
// the same aggregate snapshot; after one is applied (winner), the other is
// rejected with a typed error (loser); no partial mutations occur.

use gocode_domain::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
    WakeCondition, WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource,
};
use gocode_domain::command::{TaskRunCommand, TerminalResult};
use gocode_domain::context::ContextManifestRef;
use gocode_domain::error::{DomainError, LoopInvariantViolation};
use gocode_domain::event::{
    Actor, CommandContext, DomainEventDraft, EventEnvelope, Sensitivity, materialize_batch,
};
use gocode_domain::id::*;
use gocode_domain::plan::PlanRevisionRef;
use gocode_domain::recovery::{ReconciliationResultRef, ReconciliationStatus};
use gocode_domain::reference::{BudgetReservationRef, CheckpointRef, ResultRef};
use gocode_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use gocode_domain::timestamp::Timestamp;
use gocode_domain::verification::PlanEvaluationRef;

use gocode_application::commands::{CommandOutcome, CreateNextCycleInput};
use gocode_application::errors::ApplicationError;
use gocode_application::fingerprint::CommandFingerprint;
use gocode_application::ports::{
    ApplicationCommandContext, CommandCommit, CommitError, CommitResult, EventStore,
    EventStoreError, IdGenerationError, IdGenerator, IdempotencyScope, LoadedStream,
    PlanEvaluation, PreparedRetrySchedule, PrincipalId, ReceiptLookup, ReconciliationError,
    ReconciliationQueryPort, RetryScheduleError, RetrySchedulePort, RuntimeAuthorityId, TimeError,
    TimePort, UnitOfWork, VerificationQueryError, VerificationQueryPort, WakeEvidenceError,
    WakeEvidenceQueryPort,
};
use gocode_application::service::{AgentLoopAuthorities, TaskRunService};

const TASK: &str = "018f2e3a-7000-7000-8000-000000000001";
const ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000002";
const CYCLE: &str = "018f2e3a-7000-7000-8000-000000000003";
const OTHER: &str = "018f2e3a-7000-7000-8000-000000000004";
const ATT2: &str = "018f2e3a-7000-7000-8000-000000000005";
const CYCLE2: &str = "018f2e3a-7000-7000-8000-000000000006";

fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

fn context_ref() -> ContextManifestRef {
    ContextManifestRef {
        manifest_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        cycle_id: CYCLE.parse().unwrap(),
        revision: 1,
        policy_revision: "context-v1".into(),
        integrity_digest: digest(1),
    }
}

fn budget_ref() -> BudgetReservationRef {
    BudgetReservationRef {
        reservation_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        retry_ordinal: 1,
        reservation_digest: digest(2),
    }
}

fn plan_ref(indexes: Vec<u32>) -> PlanRevisionRef {
    PlanRevisionRef {
        plan_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        cycle_id: CYCLE.parse().unwrap(),
        revision: 1,
        context_manifest_ref: context_ref(),
        expected_proposal_indexes: indexes,
        proposal_batch_digest: digest(3),
        planning_policy_ref: ResultRef::new(OTHER.parse().unwrap(), "application/json", digest(4))
            .unwrap(),
        planning_budget_ref: budget_ref(),
        parent_ref: None,
        integrity_digest: digest(5),
    }
}

fn envelope(sequence: u64, payload: TaskRunEvent) -> EventEnvelope<TaskRunEvent> {
    let taskrun_id: TaskRunId = TASK.parse().unwrap();
    let aggregate_id = AggregateId::TaskRun(taskrun_id);
    let draft = DomainEventDraft::new(
        aggregate_id.clone(),
        aggregate_id,
        1,
        Sensitivity::Sensitive,
        payload,
    );
    let command = CommandContext {
        command_id: TASK.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("phase5-race").unwrap(),
        actor: Actor::new("phase5-race").unwrap(),
    };
    let event_id: EventId = OTHER.parse().unwrap();
    materialize_batch(vec![draft], &[event_id], None, &command)
        .unwrap()
        .remove(0)
        .into_envelope(
            sequence,
            Timestamp::from_unix_micros(sequence as i64),
            digest(0),
        )
}

fn base_loop_stream() -> Vec<EventEnvelope<TaskRunEvent>> {
    vec![
        envelope(1, TaskRunEvent::TaskRunCreated),
        envelope(2, TaskRunEvent::TaskRunQueued),
        envelope(3, TaskRunEvent::TaskRunAdmitted),
        envelope(
            4,
            TaskRunEvent::AttemptStarted {
                attempt_id: ATTEMPT.parse().unwrap(),
            },
        ),
        envelope(
            5,
            TaskRunEvent::LoopCycleStarted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                sequence: 0,
                parent_cycle_id: None,
            },
        ),
    ]
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 1: Continue successor — duplicate successor allocation loses
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_continue_successor_vs_cancellation() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::LoopCycleCompleted {
            cycle_id: CYCLE.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            disposition: LoopDisposition::Continue,
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    let before = agg.clone();

    let winner = TaskRunCommand::CreateNextCycle {
        parent_cycle_id: CYCLE.parse().unwrap(),
        successor_cycle_id: CYCLE2.parse().unwrap(),
    };
    let winner_drafts = agg.decide(winner.clone()).unwrap();
    assert!(!winner_drafts.is_empty());

    let loser_drafts = agg.decide(winner).unwrap();
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert!(after_winner.pending_successor().is_some());
    assert_ne!(after_winner, before);

    let err = after_winner
        .decide(TaskRunCommand::CreateNextCycle {
            parent_cycle_id: CYCLE.parse().unwrap(),
            successor_cycle_id: OTHER.parse().unwrap(),
        })
        .unwrap_err();
    assert!(matches!(err, DomainError::LoopInvariantViolation { .. }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 2: Wait wake — duplicate resume loses
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_loop_wait_wake_vs_cancellation() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![],
        },
    ));
    let wake_condition = WakeCondition {
        kind: WakeConditionKind::Approval,
        condition_ref: "approval:1".into(),
        condition_digest: digest(11),
    };
    stream.push(envelope(
        8,
        TaskRunEvent::LoopCycleCompleted {
            cycle_id: CYCLE.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            disposition: LoopDisposition::Wait {
                reason: "approval".into(),
                wake_condition: wake_condition.clone(),
            },
        },
    ));
    stream.push(envelope(9, TaskRunEvent::WaitStarted));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Waiting);
    assert!(agg.pending_loop_wait().is_some());
    let before = agg.clone();

    let winner = TaskRunCommand::ResumeLoopWait {
        wake_evidence_ref: WakeEvidenceRef {
            cycle_id: CYCLE.parse().unwrap(),
            condition_digest: digest(11),
            source: WakeEvidenceSource::Approval,
            evidence_id: OTHER.parse().unwrap(),
            evidence_digest: digest(12),
            observed_at_unix_us: 100,
            authority_revision: "approval-v1".into(),
        },
    };
    let loser = TaskRunCommand::RequestCancellation;

    let winner_drafts = agg.decide(winner).unwrap();
    let loser_drafts = agg.decide(loser.clone()).unwrap();
    assert!(!winner_drafts.is_empty());
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert!(after_winner.pending_loop_wait().is_none());
    assert_ne!(after_winner, before);

    // Duplicate wake on already-resumed aggregate → typed error
    let err = after_winner
        .decide(TaskRunCommand::ResumeLoopWait {
            wake_evidence_ref: WakeEvidenceRef {
                cycle_id: CYCLE.parse().unwrap(),
                condition_digest: digest(11),
                source: WakeEvidenceSource::Approval,
                evidence_id: OTHER.parse().unwrap(),
                evidence_digest: digest(13),
                observed_at_unix_us: 200,
                authority_revision: "approval-v2".into(),
            },
        })
        .unwrap_err();
    assert!(
        err.to_string().contains("wait")
            || matches!(
                err,
                DomainError::LoopInvariantViolation { .. } | DomainError::InvalidTransition { .. }
            )
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 3: Retry schedule vs completion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_retry_schedule_vs_completion() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::StepOutcomeRecorded {
            cycle_id: CYCLE.parse().unwrap(),
            outcome: StepOutcomeRecord {
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_type: StepOutcomeType::FailedBeforeCommit,
                result_ref: None,
                effect_id: None,
                evidence_digests: vec![],
            },
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    let before = agg.clone();

    let step_ref = StepOutcomeRef {
        cycle_id: CYCLE.parse().unwrap(),
        proposal_index: 0,
        step_id: OTHER.parse().unwrap(),
        outcome_digest: digest(13),
    };

    let winner = TaskRunCommand::ScheduleRetry {
        new_attempt_id: ATT2.parse().unwrap(),
        retry_ordinal: 1,
        step_outcome_ref: step_ref.clone(),
        retry_policy_digest: digest(14),
        budget_reservation_ref: budget_ref(),
        delay_ms: 100,
        due_at_unix_us: 100_000,
    };
    let loser = TaskRunCommand::Complete {
        result: TerminalResult::Success,
    };

    let winner_drafts = agg.decide(winner).unwrap();
    let loser_drafts = agg.decide(loser.clone()).unwrap();
    assert!(!winner_drafts.is_empty());
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Retrying);
    assert!(after_winner.pending_retry().is_some());
    assert_ne!(after_winner, before);

    let err = after_winner.decide(loser).unwrap_err();
    assert!(matches!(err, DomainError::InvalidTransition { .. }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 4: Retry activation vs duplicate
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_retry_activation_vs_duplicate() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::StepOutcomeRecorded {
            cycle_id: CYCLE.parse().unwrap(),
            outcome: StepOutcomeRecord {
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_type: StepOutcomeType::FailedBeforeCommit,
                result_ref: None,
                effect_id: None,
                evidence_digests: vec![],
            },
        },
    ));
    stream.push(envelope(
        9,
        TaskRunEvent::RetryScheduled {
            ordinal: 1,
            old_attempt_id: ATTEMPT.parse().unwrap(),
            new_attempt_id: ATT2.parse().unwrap(),
            abandoned_cycle_id: CYCLE.parse().unwrap(),
            step_outcome_ref: StepOutcomeRef {
                cycle_id: CYCLE.parse().unwrap(),
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_digest: digest(13),
            },
            retry_policy_digest: digest(14),
            budget_reservation_ref: budget_ref(),
            delay_ms: 25,
            due_at_unix_us: 25_100,
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Retrying);
    assert!(agg.pending_retry().is_some());
    let before = agg.clone();

    let winner = TaskRunCommand::ActivateScheduledRetryAttempt {
        retry_ordinal: 1,
        now_unix_us: 25_100,
    };
    let winner_drafts = agg.decide(winner).unwrap();
    assert!(!winner_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert!(after_winner.pending_retry().is_none());
    assert_ne!(after_winner, before);

    let err = after_winner
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 1,
            now_unix_us: 25_200,
        })
        .unwrap_err();
    assert!(matches!(err, DomainError::InvalidTransition { .. }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 5: Recovery resume vs cancellation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_recovery_resume_vs_cancellation() {
    let mut stream = base_loop_stream();
    stream.push(envelope(6, TaskRunEvent::ReconciliationStarted));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Reconciling);
    let before = agg.clone();

    let reconciliation_ref = ReconciliationResultRef {
        reconciliation_run_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        predecessor_attempt_id: ATTEMPT.parse().unwrap(),
        recovery_generation: 0,
        reconciled_stream_position: 5,
        status: ReconciliationStatus::Reconciled,
        unresolved_effect_count: 0,
        result_digest: digest(16),
    };

    let winner = TaskRunCommand::CommitRecoveryResume {
        new_attempt_id: ATT2.parse().unwrap(),
        context_manifest_ref: context_ref(),
        checkpoint_ref: CheckpointRef {
            checkpoint_id: OTHER.parse().unwrap(),
            event_position: 5,
            integrity_digest: digest(15),
        },
        reconciliation_ref: reconciliation_ref.clone(),
    };
    let winner_drafts = agg.decide(winner).unwrap();
    assert!(!winner_drafts.is_empty());

    let err = agg.decide(TaskRunCommand::RequestCancellation).unwrap_err();
    assert!(matches!(err, DomainError::InvalidTransition { .. }));

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert_eq!(after_winner.recovery_generation(), 1);
    assert_ne!(after_winner, before);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 6: Loop checkpoint vs terminal completion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_loop_checkpoint_vs_completion() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    let _before = agg.clone();

    let checkpoint_id: CheckpointId = OTHER.parse().unwrap();
    let check_body = LoopCheckpointBody {
        schema_version: "1".into(),
        cycle_id: CYCLE.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        plan_revision_ref: None,
        context_manifest_ref: Some(context_ref()),
        step_outcome_refs: vec![],
    };

    let winner = TaskRunCommand::CommitLoopCheckpoint {
        checkpoint_id,
        event_position: 7,
        body: check_body,
        integrity_digest: digest(17),
    };
    let loser = TaskRunCommand::Complete {
        result: TerminalResult::Success,
    };

    let winner_drafts = agg.decide(winner).unwrap();
    let loser_drafts = agg.decide(loser.clone()).unwrap();
    assert_eq!(winner_drafts.len(), 3);
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert!(after_winner.pending_loop_checkpoint().is_none());

    // Loser still valid on post-winner (state unchanged by checkpoint),
    // but pipeline catches version mismatch.
    let _ = after_winner.decide(loser).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-cutting: no partial mutations from failed loser
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn loser_never_causes_partial_mutations() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::StepOutcomeRecorded {
            cycle_id: CYCLE.parse().unwrap(),
            outcome: StepOutcomeRecord {
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_type: StepOutcomeType::FailedBeforeCommit,
                result_ref: None,
                effect_id: None,
                evidence_digests: vec![],
            },
        },
    ));
    stream.push(envelope(
        9,
        TaskRunEvent::RetryScheduled {
            ordinal: 1,
            old_attempt_id: ATTEMPT.parse().unwrap(),
            new_attempt_id: ATT2.parse().unwrap(),
            abandoned_cycle_id: CYCLE.parse().unwrap(),
            step_outcome_ref: StepOutcomeRef {
                cycle_id: CYCLE.parse().unwrap(),
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_digest: digest(13),
            },
            retry_policy_digest: digest(14),
            budget_reservation_ref: budget_ref(),
            delay_ms: 25,
            due_at_unix_us: 25_100,
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    let before = agg.clone();

    let err = agg
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 1,
            now_unix_us: 25_000,
        })
        .unwrap_err();
    assert_eq!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::RetryNotDue,
        }
    );
    assert_eq!(agg, before);

    let err2 = before
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 99,
            now_unix_us: 25_200,
        })
        .unwrap_err();
    assert!(matches!(err2, DomainError::LoopInvariantViolation { .. }));
    assert_eq!(before, agg);
}

// Service-level OCC version-conflict test

// (imports from top of file)

// Simple version-tracking store: load returns fixed events, commit checks OCC.
// After winner commits and advances version, loser's load sees updated version
// and pipeline returns VersionConflict (checked before domain decide).

#[derive(Clone)]
struct OccStore {
    events: Rc<RefCell<Vec<EventEnvelope<TaskRunEvent>>>>,
    version: Rc<Cell<u64>>,
}

impl OccStore {
    fn new(events: Vec<EventEnvelope<TaskRunEvent>>) -> Self {
        let v = events.last().map(|e| e.sequence()).unwrap_or(0);
        Self {
            events: Rc::new(RefCell::new(events)),
            version: Rc::new(Cell::new(v)),
        }
    }
}

impl EventStore for OccStore {
    fn load_task_run(&self, _: TaskRunId) -> Result<LoadedStream, EventStoreError> {
        let events = self.events.borrow().clone();
        let v = self.version.get();
        Ok(LoadedStream {
            current_version: v,
            last_event_id: events.last().map(|e| *e.event_id()),
            events,
        })
    }
}

impl UnitOfWork for OccStore {
    fn lookup_receipt(
        &self,
        _: CommandId,
        _: &IdempotencyKey,
        _: &IdempotencyScope,
        _: &CommandFingerprint,
    ) -> Result<ReceiptLookup, CommitError> {
        Ok(ReceiptLookup::Miss)
    }
    fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
        let cur = self.version.get();
        if payload.expected_version != cur {
            return Err(CommitError::VersionConflict {
                expected: payload.expected_version,
                actual: cur,
            });
        }
        let nv = cur + payload.events.len() as u64;
        // Append committed events to keep version/event-count consistent
        let mut ev = self.events.borrow_mut();
        let mut seq = cur;
        for ue in &payload.events {
            seq += 1;
            ev.push(envelope(seq, ue.payload().clone()));
        }
        self.version.set(nv);
        Ok(CommitResult::Committed { new_version: nv })
    }
}

const GEN_ID: &str = "018f2e3a-7000-7000-8000-000000000010";
struct OI;
impl IdGenerator for OI {
    fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
        Ok(TASK.parse().unwrap())
    }
    fn next_conversation_id(&self) -> Result<gocode_domain::id::ConversationId, IdGenerationError> {
        Ok(OTHER.parse().unwrap())
    }
    fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
        Ok(ATT2.parse().unwrap())
    }
    fn next_cycle_id(&self) -> Result<gocode_domain::id::CycleId, IdGenerationError> {
        Ok(OTHER.parse().unwrap())
    }
    fn next_checkpoint_id(&self) -> Result<gocode_domain::id::CheckpointId, IdGenerationError> {
        Ok(OTHER.parse().unwrap())
    }
    fn next_event_ids(
        &self,
        c: usize,
    ) -> Result<Vec<gocode_domain::id::EventId>, IdGenerationError> {
        Ok((0..c).map(|_| GEN_ID.parse().unwrap()).collect())
    }
}

struct OT;
impl TimePort for OT {
    fn now_unix_us(&self) -> Result<i64, TimeError> {
        Ok(0)
    }
}
struct OR;
impl RetrySchedulePort for OR {
    fn prepare(
        &self,
        _: TaskRunId,
        _: AttemptId,
        _: u64,
        _: &StepOutcomeRef,
        p: &IntegrityDigest,
        b: &BudgetReservationRef,
        n: i64,
    ) -> Result<PreparedRetrySchedule, RetryScheduleError> {
        Ok(PreparedRetrySchedule {
            retry_policy_digest: *p,
            budget_reservation_ref: b.clone(),
            delay_ms: 1,
            due_at_unix_us: n + 1000,
        })
    }
}
struct OW;
impl WakeEvidenceQueryPort for OW {
    fn validate_current(
        &self,
        _: &WakeEvidenceRef,
        _: TaskRunId,
        _: gocode_domain::id::CycleId,
        _: &WakeCondition,
    ) -> Result<(), WakeEvidenceError> {
        Ok(())
    }
}
struct OC;
impl ReconciliationQueryPort for OC {
    fn validate_current(
        &self,
        _: &gocode_domain::recovery::ReconciliationResultRef,
        _: TaskRunId,
        _: AttemptId,
        _: u64,
        _: u64,
    ) -> Result<(), ReconciliationError> {
        Ok(())
    }
}
struct OV;
impl VerificationQueryPort for OV {
    fn get_exact(&self, _: &PlanEvaluationRef) -> Result<PlanEvaluation, VerificationQueryError> {
        panic!("unexpected")
    }
}

fn oc_ctx(key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: TASK.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("p".into()),
        actor: Actor::new("p").unwrap(),
    }
}

/// Two concurrent CreateNextCycle commands on the same version.
/// Winner commits and advances version; loser hits VersionConflict via the pipeline.
#[test]
fn pipeline_version_conflict_two_create_next_cycle() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![],
        },
    ));
    stream.push(envelope(
        8,
        TaskRunEvent::LoopCycleCompleted {
            cycle_id: CYCLE.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            disposition: LoopDisposition::Continue,
        },
    ));

    let tr: TaskRunId = TASK.parse().unwrap();
    let store = OccStore::new(stream);
    let svc = TaskRunService::with_agent_loop_authorities(
        store.clone(),
        store.clone(),
        OI,
        RuntimeAuthorityId("t".into()),
        AgentLoopAuthorities {
            time: OT,
            retry_schedule: OR,
            wake_evidence: OW,
            reconciliation: OC,
            verification: OV,
        },
    );

    let w = svc.create_next_cycle(
        &oc_ctx("w"),
        CreateNextCycleInput {
            taskrun_id: tr,
            expected_version: 8,
            parent_cycle_id: CYCLE.parse().unwrap(),
        },
    );
    assert!(
        matches!(w, Ok(CommandOutcome::NextCycleAllocated { .. })),
        "winner: {:?}",
        w
    );

    let l = svc.create_next_cycle(
        &oc_ctx("l"),
        CreateNextCycleInput {
            taskrun_id: tr,
            expected_version: 8,
            parent_cycle_id: CYCLE.parse().unwrap(),
        },
    );
    assert!(
        matches!(l, Err(ApplicationError::VersionConflict { .. })),
        "loser: {:?}",
        l
    );
}
