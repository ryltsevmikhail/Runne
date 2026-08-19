    use super::*;
    use crate::event::{Actor, CommandContext, materialize_batch};
    use crate::id::{IdempotencyKey, IntegrityDigest, TaskRunId};
    use crate::timestamp::Timestamp;

    const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000000";
    const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const OTHER_WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000004";
    const USER_MESSAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000005";
    const ASSISTANT_MESSAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000006";

    fn make_envelope(
        sequence: u64,
        payload: ConversationEvent,
        aggregate_id: AggregateId,
        correlation_id: AggregateId,
    ) -> EventEnvelope<ConversationEvent> {
        let sensitivity = payload.sensitivity();
        let draft = DomainEventDraft::new(aggregate_id, correlation_id, 1, sensitivity, payload);
        let context = CommandContext {
            command_id: CONVERSATION_ID.parse().expect("valid UUIDv7"),
            idempotency_key: IdempotencyKey::new("test").expect("valid idempotency key"),
            actor: Actor::new("test").expect("valid actor"),
        };
        let event_ids = &[CONVERSATION_ID.parse().expect("valid UUIDv7")];
        materialize_batch(vec![draft], event_ids, None, &context)
            .expect("one materialized event")
            .pop()
            .expect("one uncommitted event")
            .into_envelope(
                sequence,
                Timestamp::from_unix_micros(1_000),
                IntegrityDigest::from_bytes([0; 32]),
            )
    }

    fn conversation_id() -> ConversationId {
        CONVERSATION_ID.parse().expect("valid UUIDv7")
    }

    fn workspace_id() -> WorkspaceId {
        WORKSPACE_ID.parse().expect("valid UUIDv7")
    }

    fn other_workspace_id() -> WorkspaceId {
        OTHER_WORKSPACE_ID.parse().expect("valid UUIDv7")
    }

    fn conversation_aggregate_id() -> AggregateId {
        AggregateId::Conversation(conversation_id())
    }

    fn taskrun_id() -> TaskRunId {
        TASKRUN_ID.parse().expect("valid UUIDv7")
    }

    fn attempt_id() -> AttemptId {
        ATTEMPT_ID.parse().expect("valid UUIDv7")
    }

    fn user_message_id() -> MessageId {
        USER_MESSAGE_ID.parse().expect("valid UUIDv7")
    }

    fn assistant_message_id() -> MessageId {
        ASSISTANT_MESSAGE_ID.parse().expect("valid UUIDv7")
    }

    fn conversation(state: ConversationState) -> Conversation {
        Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state,
            messages: Vec::new(),
            active_generation: None,
        }
    }
