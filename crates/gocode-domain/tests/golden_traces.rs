//! L1 golden traces — canonical command → events → state fixtures.
//!
//! These are checked-in, human-reviewed expected values.
//! Test code MUST NOT generate its own expected output from the system
//! under test.

use gocode_domain::command::{CreateTaskRun, TaskRunCommand, TerminalResult};
use gocode_domain::id::{AggregateId, AttemptId, IdempotencyKey, TaskRunId};
use gocode_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};

const TR_ID: &str = "018f2e3a-7000-7000-8000-000000000000";
const WS_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
const CONV_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
const ATT_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
const ATT_ID2: &str = "018f2e3a-7000-7000-8000-000000000004";

/// Helper: create a TaskRun aggregate in Created state via replay.
fn created_aggregate() -> TaskRun {
    use gocode_domain::event::{
        Actor, CommandContext, DomainEventDraft, Sensitivity, materialize_batch,
    };
    use gocode_domain::id::IntegrityDigest;
    use gocode_domain::timestamp::Timestamp;

    let tr_id: TaskRunId = TR_ID.parse().unwrap();
    let draft = DomainEventDraft::new(
        AggregateId::TaskRun(tr_id),
        tr_id,
        1,
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
    );
    let ctx = CommandContext {
        command_id: TR_ID.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("golden").unwrap(),
        actor: Actor::new("golden").unwrap(),
    };
    let ids = &[TR_ID.parse::<gocode_domain::id::EventId>().unwrap()];
    let uncommitted = materialize_batch(vec![draft], ids, None, &ctx)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let envelope = uncommitted.into_envelope(
        1,
        Timestamp::from_unix_micros(1000),
        IntegrityDigest::from_bytes([0; 32]),
    );

    TaskRun::replay(&[envelope]).unwrap()
}

// ─── Golden trace 1: CreateTaskRun → TaskRunCreated → state=Created ───────

#[test]
fn golden_create_task_run() {
    let cmd = CreateTaskRun {
        taskrun_id: TR_ID.parse().unwrap(),
        conversation_id: CONV_ID.parse().unwrap(),
        workspace_id: WS_ID.parse().unwrap(),
    };

    let draft = TaskRun::decide_create(cmd).unwrap();

    // Expected: TaskRunCreated event
    assert_eq!(*draft.payload(), TaskRunEvent::TaskRunCreated);
    assert_eq!(draft.schema_version(), 1);

    // Expected aggregate ID
    let expected_agg_id: AggregateId = AggregateId::TaskRun(TR_ID.parse().unwrap());
    assert_eq!(*draft.aggregate_id(), expected_agg_id);
}

// ─── Golden trace 2: Created + TaskRunQueued → Queued ──────────────────────

#[test]
fn golden_created_to_queued() {
    let mut agg = created_aggregate();
    assert_eq!(agg.state(), TaskRunState::Created);

    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();

    // Expected: state is Queued
    assert_eq!(agg.state(), TaskRunState::Queued);
}

// ─── Golden trace 3: Queued + Admit → Admitted ─────────────────────────────

#[test]
fn golden_queued_to_admitted() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();

    let drafts = agg.decide(TaskRunCommand::Admit).unwrap();

    // Expected: single TaskRunAdmitted event
    assert_eq!(drafts.len(), 1);
    assert_eq!(*drafts[0].payload(), TaskRunEvent::TaskRunAdmitted);

    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    assert_eq!(agg.state(), TaskRunState::Admitted);
}

// ─── Golden trace 4: Admitted + AttemptStarted → Running ──────────────────

#[test]
fn golden_admitted_to_running() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();

    let aid: AttemptId = ATT_ID.parse().unwrap();
    let drafts = agg
        .decide(TaskRunCommand::StartAttempt { attempt_id: aid })
        .unwrap();

    // Expected: single AttemptStarted with correct attempt_id
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        *drafts[0].payload(),
        TaskRunEvent::AttemptStarted { attempt_id: aid }
    );

    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    assert_eq!(agg.active_attempt(), Some(&aid));
    assert_eq!(agg.attempt_history(), &[aid]);
}

// ─── Golden trace 5: Running + Complete(Success) → Succeeded ──────────────

#[test]
fn golden_running_to_succeeded() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid: AttemptId = ATT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();

    let drafts = agg
        .decide(TaskRunCommand::Complete {
            result: TerminalResult::Success,
        })
        .unwrap();

    // Expected: TaskRunCompleted with Success
    assert_eq!(
        *drafts[0].payload(),
        TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success
        }
    );

    agg.apply_payload(&TaskRunEvent::TaskRunCompleted {
        result: TerminalResult::Success,
    })
    .unwrap();
    assert_eq!(agg.state(), TaskRunState::Succeeded);
    assert!(agg.state().is_terminal());
    assert_eq!(agg.terminal_result(), Some(&TerminalResult::Success));
    assert!(agg.active_attempt().is_none());
}

// ─── Golden trace 6: Cancellation path ────────────────────────────────────

#[test]
fn golden_cancellation_request_then_complete() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid: AttemptId = ATT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();

    // Step 1: request cancellation
    let drafts = agg.decide(TaskRunCommand::RequestCancellation).unwrap();
    assert_eq!(*drafts[0].payload(), TaskRunEvent::CancellationRequested);

    agg.apply_payload(&TaskRunEvent::CancellationRequested)
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Cancelling);

    // Step 2: complete cancellation
    let drafts = agg.decide(TaskRunCommand::CompleteCancellation).unwrap();
    assert_eq!(*drafts[0].payload(), TaskRunEvent::CancellationCompleted);

    agg.apply_payload(&TaskRunEvent::CancellationCompleted)
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Cancelled);
    assert!(agg.active_attempt().is_none());
}

// ─── Golden trace 7: Invalid transition → DomainError ─────────────────────

#[test]
fn golden_invalid_transition_created_to_attempt_started() {
    let agg = created_aggregate();
    let aid: AttemptId = ATT_ID.parse().unwrap();

    let err = agg
        .decide(TaskRunCommand::StartAttempt { attempt_id: aid })
        .unwrap_err();

    // Expected: InvalidTransition from Created with AttemptStarted kind
    assert!(matches!(
        err,
        gocode_domain::error::DomainError::InvalidTransition { .. }
    ));
}

// ─── Golden trace 8: Replay round-trip ────────────────────────────────────

#[test]
fn golden_replay_roundtrip_complete_lifecycle() {
    use gocode_domain::event::EventEnvelope;
    use gocode_domain::event::{
        Actor, CommandContext, DomainEventDraft, Sensitivity, materialize_batch,
    };
    use gocode_domain::id::IntegrityDigest;
    use gocode_domain::timestamp::Timestamp;

    let tr_id: TaskRunId = TR_ID.parse().unwrap();
    let aid: AttemptId = ATT_ID.parse().unwrap();

    fn make_envelope(
        seq: u64,
        payload: TaskRunEvent,
        tr_id: TaskRunId,
    ) -> EventEnvelope<TaskRunEvent> {
        let draft = DomainEventDraft::new(
            AggregateId::TaskRun(tr_id),
            tr_id,
            1,
            Sensitivity::Public,
            payload,
        );
        let ctx = CommandContext {
            command_id: "018f2e3a-7000-7000-8000-000000000000".parse().unwrap(),
            idempotency_key: IdempotencyKey::new("roundtrip").unwrap(),
            actor: Actor::new("roundtrip").unwrap(),
        };
        let ids = &["018f2e3a-7000-7000-8000-000000000000"
            .parse::<gocode_domain::id::EventId>()
            .unwrap()];
        let ue = materialize_batch(vec![draft], ids, None, &ctx)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        ue.into_envelope(
            seq,
            Timestamp::from_unix_micros(1000),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

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

    // Expected: Succeeded, 1 attempt in history, matching ID
    assert_eq!(agg.state(), TaskRunState::Succeeded);
    assert_eq!(*agg.id(), tr_id);
    assert_eq!(agg.attempt_history(), &[aid]);
    assert_eq!(agg.terminal_result(), Some(&TerminalResult::Success));
    assert!(agg.active_attempt().is_none());
}

// ─── Golden trace 9: Retry cycle with new attempt ID ──────────────────────

#[test]
fn golden_retry_with_new_attempt() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid1: AttemptId = ATT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid1 })
        .unwrap();

    let aid2: AttemptId = ATT_ID2.parse().unwrap();
    let drafts = agg
        .decide(TaskRunCommand::StartRetry { attempt_id: aid2 })
        .unwrap();
    assert_eq!(
        *drafts[0].payload(),
        TaskRunEvent::RetryStarted { attempt_id: aid2 }
    );

    agg.apply_payload(&TaskRunEvent::RetryStarted { attempt_id: aid2 })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Retrying);
    assert_eq!(agg.active_attempt(), Some(&aid2));
    assert_eq!(agg.attempt_history(), &[aid1, aid2]);

    // Complete retry
    agg.apply_payload(&TaskRunEvent::RetryCompleted { attempt_id: aid2 })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    assert_eq!(agg.active_attempt(), Some(&aid2));
}
