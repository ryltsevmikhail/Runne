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
