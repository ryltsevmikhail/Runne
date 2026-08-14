use gocode_api::{ReplayPromotionProjectionV1, UnauthenticatedReplayPromotionProjectionV1};
use gocode_domain::conversation::Conversation;
use gocode_domain::event::{Actor, EventEnvelope};
use gocode_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, MessageId,
    TaskRunId, WorkspaceId,
};
use gocode_domain::message::MessageText;
use gocode_domain::task_run::{TaskRun, TaskRunEvent};
use gocode_domain::timestamp::Timestamp;

#[test]
fn local_promotion_json_preserves_conversation_message_timestamp_and_text() {
    let id = ConversationId::from_bytes(uuid(1));
    let create = Conversation::decide_create(id, WorkspaceId::from_bytes(uuid(2)));
    let aggregate = create.aggregate_id().clone();
    let created = EventEnvelope::from_parts(
        EventId::from_bytes(uuid(3)),
        aggregate.clone(),
        aggregate.clone(),
        None,
        CommandId::from_bytes(uuid(4)),
        IdempotencyKey::new("local-json").unwrap(),
        1,
        Actor::new("test").unwrap(),
        *create.sensitivity(),
        create.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([7; 32]),
    );
    let message = gocode_domain::conversation::ConversationEvent::UserMessageAppended {
        message_id: MessageId::from_bytes(uuid(5)),
        taskrun_id: TaskRunId::from_bytes(uuid(6)),
        attempt_id: AttemptId::from_bytes(uuid(7)),
        text: MessageText::new("exact historical text").unwrap(),
    };
    let appended = EventEnvelope::from_parts(
        EventId::from_bytes(uuid(8)),
        aggregate.clone(),
        aggregate,
        Some(*created.event_id()),
        CommandId::from_bytes(uuid(9)),
        IdempotencyKey::new("local-json-message").unwrap(),
        1,
        Actor::new("test").unwrap(),
        gocode_domain::event::Sensitivity::Sensitive,
        message,
        2,
        Timestamp::from_unix_micros(1_723_500_000_123_456),
        IntegrityDigest::from_bytes([8; 32]),
    );
    let conversation = Conversation::replay(&[created, appended]).unwrap();
    let bytes = ReplayPromotionProjectionV1::encode_conversation(
        &conversation.snapshot_v1(),
        &[Timestamp::from_unix_micros(1_723_500_000_123_456)],
    )
    .unwrap();
    let projection = UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).unwrap();

    let json = gocode_api::canonical_local_promotion_json(projection.view()).unwrap();
    assert_eq!(json["kind"], "conversation");
    assert_eq!(json["state"], "active");
    assert_eq!(json["messages"][0]["text"], "exact historical text");
    assert_eq!(
        json["messages"][0]["committedAtMicros"],
        1_723_500_000_123_456_i64
    );
}

#[test]
fn local_promotion_json_preserves_taskrun_state_fields() {
    let id = gocode_domain::id::TaskRunId::from_bytes(uuid(9));
    let attempt = AttemptId::from_bytes(uuid(20));
    let cycle = gocode_domain::id::CycleId::from_bytes(uuid(21));
    let events = vec![
        task_event(id, 1, TaskRunEvent::TaskRunCreated),
        task_event(id, 2, TaskRunEvent::TaskRunQueued),
        task_event(id, 3, TaskRunEvent::TaskRunAdmitted),
        task_event(
            id,
            4,
            TaskRunEvent::AttemptStarted {
                attempt_id: attempt,
            },
        ),
        task_event(
            id,
            5,
            TaskRunEvent::LoopCycleStarted {
                cycle_id: cycle,
                attempt_id: attempt,
                sequence: 0,
                parent_cycle_id: None,
            },
        ),
    ];
    let bytes = ReplayPromotionProjectionV1::encode_task_run(
        &TaskRun::replay(&events).unwrap().snapshot_v1(),
    )
    .unwrap();
    let projection = UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).unwrap();

    let json = gocode_api::canonical_local_promotion_json(projection.view()).unwrap();
    assert_eq!(json["kind"], "task_run");
    assert_eq!(json["state"]["lifecycle"], "running");
    assert_eq!(
        json["state"]["attemptHistory"][0],
        "018f2e3a700070008000000000000014"
    );
    assert_eq!(
        json["state"]["activeCycle"]["cycleId"],
        "018f2e3a700070008000000000000015"
    );
    assert_eq!(json["state"]["activeCycle"]["state"], "observing");
}

fn task_event(
    id: gocode_domain::id::TaskRunId,
    sequence: u64,
    payload: TaskRunEvent,
) -> EventEnvelope<TaskRunEvent> {
    let marker = u8::try_from(30 + sequence).unwrap();
    EventEnvelope::from_parts(
        EventId::from_bytes(uuid(marker)),
        gocode_domain::id::AggregateId::TaskRun(id),
        gocode_domain::id::AggregateId::TaskRun(id),
        (sequence > 1).then(|| EventId::from_bytes(uuid(marker - 1))),
        CommandId::from_bytes(uuid(marker)),
        IdempotencyKey::new(format!("taskrun-local-json-{sequence}")).unwrap(),
        1,
        Actor::new("test").unwrap(),
        gocode_domain::event::Sensitivity::Public,
        payload,
        sequence,
        Timestamp::from_unix_micros(i64::try_from(sequence).unwrap()),
        IntegrityDigest::from_bytes([marker; 32]),
    )
}

fn uuid(last: u8) -> [u8; 16] {
    [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, last]
}
