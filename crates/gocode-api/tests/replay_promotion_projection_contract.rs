use gocode_api::{
    ReplayPromotionProjectionV1, ReplayPromotionProjectionViewV1,
    UnauthenticatedReplayPromotionProjectionV1,
};
use gocode_domain::conversation::{Conversation, ConversationEvent};
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest,
    MessageId, TaskRunId, WorkspaceId,
};
use gocode_domain::message::MessageText;
use gocode_domain::task_run::{TaskRun, TaskRunEvent};
use gocode_domain::timestamp::Timestamp;

const ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[test]
fn promotion_projection_exposes_ordered_conversation_messages_with_envelope_times() {
    let conversation = conversation();
    let bytes = ReplayPromotionProjectionV1::encode_conversation(
        &conversation.snapshot_v1(),
        &[
            Timestamp::from_unix_micros(10),
            Timestamp::from_unix_micros(20),
        ],
    )
    .unwrap();

    let decoded = UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).unwrap();
    let ReplayPromotionProjectionViewV1::Conversation(view) = decoded.view() else {
        panic!("expected Conversation promotion view");
    };
    assert_eq!(view.aggregate_id(), ID);
    assert_eq!(view.workspace_id(), uuid(2));
    assert_eq!(view.messages().len(), 2);
    assert_eq!(view.messages()[0].message_id(), uuid(5));
    assert_eq!(view.messages()[0].role().as_str(), "user");
    assert_eq!(view.messages()[0].text(), "hello");
    assert_eq!(view.messages()[0].committed_at_micros(), 10);
    assert_eq!(view.messages()[1].role().as_str(), "assistant");
    assert_eq!(view.messages()[1].text(), "world");
    assert_eq!(view.messages()[1].committed_at_micros(), 20);
    assert!(format!("{decoded:?}").contains("redacted"));
    assert!(!format!("{decoded:?}").contains("hello"));
}

#[test]
fn promotion_projection_rejects_untrusted_envelope_shape_and_time_mutations() {
    let conversation = conversation();
    let bytes = ReplayPromotionProjectionV1::encode_conversation(
        &conversation.snapshot_v1(),
        &[
            Timestamp::from_unix_micros(10),
            Timestamp::from_unix_micros(20),
        ],
    )
    .unwrap();
    let snapshot_length = u32::from_be_bytes(bytes[22..26].try_into().unwrap()) as usize;
    let count_offset = 26 + snapshot_length;
    let timestamp_offset = count_offset + 4;
    let mut invalid_cardinality = bytes.clone();
    invalid_cardinality[count_offset..count_offset + 4].copy_from_slice(&1u32.to_be_bytes());
    let mut zero_timestamp = bytes.clone();
    zero_timestamp[timestamp_offset..timestamp_offset + 8].copy_from_slice(&0i64.to_be_bytes());
    let mut negative_timestamp = bytes.clone();
    negative_timestamp[timestamp_offset..timestamp_offset + 8]
        .copy_from_slice(&(-1i64).to_be_bytes());
    let mut wrong_id = bytes.clone();
    wrong_id[6..22].copy_from_slice(&uuid(9));
    let mut wrong_kind = bytes.clone();
    wrong_kind[5] = 2;

    for invalid in [
        bytes[..bytes.len() - 1].to_vec(),
        {
            let mut trailing = bytes.clone();
            trailing.push(0);
            trailing
        },
        invalid_cardinality,
        zero_timestamp,
        negative_timestamp,
        wrong_id,
        wrong_kind,
        vec![0; 512 * 1024 + 1],
    ] {
        assert!(UnauthenticatedReplayPromotionProjectionV1::decode(&invalid).is_err());
    }
}

#[test]
fn promotion_projection_exposes_a_typed_taskrun_state_without_raw_snapshot_bytes() {
    let taskrun_id = TaskRunId::from_bytes(ID);
    let event = EventEnvelope::from_parts(
        EventId::from_bytes(uuid(8)),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        CommandId::from_bytes(uuid(9)),
        IdempotencyKey::new("promotion-taskrun").unwrap(),
        1,
        Actor::new("test").unwrap(),
        Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([1; 32]),
    );
    let taskrun = TaskRun::replay(&[event]).unwrap();
    let bytes = ReplayPromotionProjectionV1::encode_task_run(&taskrun.snapshot_v1()).unwrap();

    let decoded = UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).unwrap();
    let ReplayPromotionProjectionViewV1::TaskRun(view) = decoded.view() else {
        panic!("expected TaskRun promotion view");
    };
    assert_eq!(view.aggregate_id(), ID);
    assert_eq!(view.semantic_state().lifecycle().as_str(), "created");
    assert!(view.semantic_state().attempt_history().is_empty());
    assert!(view.semantic_state().active_cycle().is_none());
    assert_ne!(view.closed_snapshot_digest(), &[0; 32]);
}

fn conversation() -> Conversation {
    let conversation_id = ConversationId::from_bytes(ID);
    let workspace_id = WorkspaceId::from_bytes(uuid(2));
    let message = |sequence: u64, event_id: u8, payload: ConversationEvent| {
        EventEnvelope::from_parts(
            EventId::from_bytes(uuid(event_id)),
            AggregateId::Conversation(conversation_id),
            AggregateId::Conversation(conversation_id),
            None,
            CommandId::from_bytes(uuid(event_id + 20)),
            IdempotencyKey::new(format!("promotion-{sequence}")).unwrap(),
            1,
            Actor::new("test").unwrap(),
            payload.sensitivity(),
            payload,
            sequence,
            Timestamp::from_unix_micros(sequence.try_into().unwrap()),
            IntegrityDigest::from_bytes([sequence as u8; 32]),
        )
    };
    Conversation::replay(&[
        message(
            1,
            3,
            ConversationEvent::ConversationCreated { workspace_id },
        ),
        message(
            2,
            4,
            ConversationEvent::UserMessageAppended {
                message_id: MessageId::from_bytes(uuid(5)),
                taskrun_id: TaskRunId::from_bytes(uuid(3)),
                attempt_id: AttemptId::from_bytes(uuid(4)),
                text: MessageText::new("hello").unwrap(),
            },
        ),
        message(
            3,
            6,
            ConversationEvent::AssistantMessageAppended {
                message_id: MessageId::from_bytes(uuid(6)),
                taskrun_id: TaskRunId::from_bytes(uuid(3)),
                attempt_id: AttemptId::from_bytes(uuid(4)),
                text: MessageText::new("world").unwrap(),
            },
        ),
    ])
    .unwrap()
}

fn uuid(last: u8) -> [u8; 16] {
    [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        last,
    ]
}
