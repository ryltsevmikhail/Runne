use crate::ReplayPromotionProjectionV1;
pub use crate::protected_activation::test_support::{admission, claims, into_untrusted_admission};
use gocode_domain::conversation::{Conversation, ConversationEvent};
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, MessageId,
    TaskRunId, WorkspaceId,
};
use gocode_domain::message::MessageText;
use gocode_domain::timestamp::Timestamp;

/// Creates a complete Conversation promotion fixture for native host tests.
#[must_use]
pub fn conversation_promotion_bytes(conversation_id: [u8; 16], workspace_id: [u8; 16]) -> Vec<u8> {
    let id = ConversationId::from_bytes(conversation_id);
    let command = Conversation::decide_create(id, WorkspaceId::from_bytes(workspace_id));
    let aggregate = command.aggregate_id().clone();
    let created = envelope(
        bytes(1),
        aggregate.clone(),
        None,
        command.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        Sensitivity::Public,
    );
    let committed = Timestamp::from_unix_micros(1_722_330_000_000_002);
    let appended = envelope(
        bytes(3),
        aggregate,
        Some(*created.event_id()),
        ConversationEvent::UserMessageAppended {
            message_id: MessageId::from_bytes(bytes(4)),
            taskrun_id: TaskRunId::from_bytes(bytes(5)),
            attempt_id: AttemptId::from_bytes(bytes(6)),
            text: MessageText::new("promoted historical text").expect("fixture"),
        },
        2,
        committed,
        Sensitivity::Sensitive,
    );
    ReplayPromotionProjectionV1::encode_conversation(
        &Conversation::replay(&[created, appended])
            .expect("fixture")
            .snapshot_v1(),
        &[committed],
    )
    .expect("fixture")
}

fn envelope<T: Clone>(
    event: [u8; 16],
    aggregate: gocode_domain::id::AggregateId,
    previous: Option<EventId>,
    payload: T,
    sequence: u64,
    timestamp: Timestamp,
    sensitivity: Sensitivity,
) -> EventEnvelope<T> {
    EventEnvelope::from_parts(
        EventId::from_bytes(event),
        aggregate.clone(),
        aggregate,
        previous,
        CommandId::from_bytes(bytes(9)),
        IdempotencyKey::new(format!("api-fixture-{sequence}")).expect("fixture"),
        1,
        Actor::new("test").expect("fixture"),
        sensitivity,
        payload,
        sequence,
        timestamp,
        IntegrityDigest::from_bytes([sequence as u8; 32]),
    )
}

const fn bytes(last: u8) -> [u8; 16] {
    [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, last]
}
