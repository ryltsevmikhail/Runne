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
        AggregateId::TaskRun(tr_id),
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

include!("golden_traces/first.rs");
include!("golden_traces/second.rs");
