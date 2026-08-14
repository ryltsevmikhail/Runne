use gocode_api::{
    ApiReplayAggregateKind, ApiReplayBindingId, ApiReplayBindingV1, ApiReplayEventSchema,
    LocalSessionContractError, ReplayContractError, RetentionManifest, RuntimeSessionBinding,
    StableRuntimeBinding,
};
use gocode_domain::conversation::Conversation;
use gocode_domain::event::EventType;
use gocode_domain::event::Sensitivity;
use gocode_domain::id::EventLogLineageId;
use gocode_domain::id::{ConversationId, WorkspaceId};
use gocode_domain::replay::ReplayScope;
use gocode_domain::task_run::{TaskRun, TaskRunEvent};

const UUID_V7: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const SESSION_ID: [u8; 16] = [7; 16];
const CERTIFICATE_SHA256: [u8; 32] = [8; 32];

fn event_schema_capabilities() -> [ApiReplayEventSchema; 1] {
    [ApiReplayEventSchema::new("conversation.message_added", 1).unwrap()]
}

#[test]
fn replay_scope_allows_only_conversation_and_taskrun_aggregates() {
    assert_eq!(
        ApiReplayAggregateKind::try_from(ReplayScope::Aggregate {
            aggregate_type: 1,
            aggregate_id: UUID_V7,
        }),
        Ok(ApiReplayAggregateKind::TaskRun)
    );
    assert_eq!(
        ApiReplayAggregateKind::try_from(ReplayScope::Aggregate {
            aggregate_type: 2,
            aggregate_id: UUID_V7,
        }),
        Ok(ApiReplayAggregateKind::Conversation)
    );
    assert_eq!(
        ApiReplayAggregateKind::try_from(ReplayScope::Aggregate {
            aggregate_type: 3,
            aggregate_id: UUID_V7,
        }),
        Err(ReplayContractError::UnknownAggregateKind)
    );
    assert_eq!(
        ApiReplayAggregateKind::try_from(ReplayScope::TaskRunFeed {
            taskrun_id: UUID_V7,
        }),
        Err(ReplayContractError::UnsupportedScope)
    );
    assert_eq!(
        ApiReplayAggregateKind::try_from(ReplayScope::AuditFeed {
            authority_id: UUID_V7,
            scope_id: UUID_V7,
        }),
        Err(ReplayContractError::UnsupportedScope)
    );
}

#[test]
fn replay_binding_rejects_session_inconsistent_authorization_and_sensitivity() {
    let stable = StableRuntimeBinding::new(
        UUID_V7,
        gocode_api::ApiPrincipalId::new("local-owner").unwrap(),
        "018f2e3a-7000-7000-8000-000000000002"
            .parse::<EventLogLineageId>()
            .unwrap(),
        "local-default",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let session = RuntimeSessionBinding::new(
        stable,
        gocode_api::DaemonInstanceId::from_bytes(UUID_V7),
        1,
        SESSION_ID,
        7,
        Sensitivity::Internal,
        CERTIFICATE_SHA256,
    )
    .unwrap();

    assert_eq!(
        ApiReplayBindingV1::new(
            ApiReplayBindingId::new([6; 16]).unwrap(),
            session.clone(),
            8,
            Sensitivity::Internal,
            event_schema_capabilities(),
            UUID_V7,
            RetentionManifest::new(1, [9; 32]).unwrap(),
        ),
        Err(LocalSessionContractError::AuthorizationEpochMismatch)
    );
    assert_eq!(
        ApiReplayBindingV1::new(
            ApiReplayBindingId::new([6; 16]).unwrap(),
            session,
            7,
            Sensitivity::Sensitive,
            event_schema_capabilities(),
            UUID_V7,
            RetentionManifest::new(1, [9; 32]).unwrap(),
        ),
        Err(LocalSessionContractError::SensitivityCeilingMismatch)
    );
}

#[test]
fn replay_binding_uses_an_opaque_id_and_validated_event_schema_pairs() {
    assert_eq!(
        ApiReplayBindingId::new([0; 16]),
        Err(ReplayContractError::EmptyBindingId)
    );
    assert_eq!(
        ApiReplayEventSchema::new("", 1),
        Err(ReplayContractError::EmptyEventType)
    );
    assert_eq!(
        ApiReplayEventSchema::new("conversation.message_added", 0),
        Err(ReplayContractError::InvalidEventSchemaVersion)
    );

    let capability = ApiReplayEventSchema::new("conversation.message_added", 1)
        .expect("a canonical event/schema pair must be accepted");
    assert_eq!(capability.event_type(), "conversation.message_added");
    assert_eq!(capability.schema_version(), 1);
}

#[test]
fn replay_capability_accepts_every_valid_canonical_event_type() {
    let canonical_event_type = EventType::new("conversation\nmessage_added")
        .expect("the domain accepts non-empty event types within its byte bound");
    let capability = ApiReplayEventSchema::new(canonical_event_type.as_str(), 1)
        .expect("replay capabilities must accept valid canonical event types");

    assert_eq!(capability.event_type(), canonical_event_type.as_str());
    assert_eq!(capability.schema_version(), 1);
}

#[test]
fn replay_projection_is_closed_and_round_trips_complete_conversation_state() {
    let conversation_id = ConversationId::from_bytes(UUID_V7);
    let workspace_id = WorkspaceId::from_bytes([
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);
    let created = Conversation::decide_create(conversation_id, workspace_id);
    let event = gocode_domain::event::EventEnvelope::from_parts(
        gocode_domain::id::EventId::from_bytes([3; 16]),
        created.aggregate_id().clone(),
        created.correlation_id().clone(),
        None,
        gocode_domain::id::CommandId::from_bytes([4; 16]),
        gocode_domain::id::IdempotencyKey::new("projection").unwrap(),
        1,
        gocode_domain::event::Actor::new("test").unwrap(),
        *created.sensitivity(),
        created.payload().clone(),
        1,
        gocode_domain::timestamp::Timestamp::from_unix_micros(1),
        gocode_domain::id::IntegrityDigest::from_bytes([5; 32]),
    );
    let conversation = Conversation::replay(&[event]).unwrap();

    let projection = gocode_api::ReplayAggregateProjectionV1::from_conversation(&conversation)
        .expect("complete aggregate snapshot must be closed and encodable");
    assert_eq!(
        projection.aggregate_kind(),
        ApiReplayAggregateKind::Conversation
    );
    assert_eq!(projection.aggregate_id(), *conversation_id.as_bytes());
    let parsed = gocode_api::UnauthenticatedReplayProjectionV1::decode_conversation_bytes(
        projection.encoded_bytes(),
    )
    .unwrap();
    assert_eq!(parsed.aggregate_kind(), projection.aggregate_kind());
    assert_eq!(parsed.aggregate_id(), projection.aggregate_id());
    assert_eq!(parsed.projection_digest(), projection.projection_digest());
}

#[test]
fn replay_projection_rejects_tamper_unknown_tag_and_trailing_bytes() {
    let conversation_id = ConversationId::from_bytes(UUID_V7);
    let workspace_id = WorkspaceId::from_bytes([
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);
    let draft = Conversation::decide_create(conversation_id, workspace_id);
    let event = gocode_domain::event::EventEnvelope::from_parts(
        gocode_domain::id::EventId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 3,
        ]),
        draft.aggregate_id().clone(),
        draft.correlation_id().clone(),
        None,
        gocode_domain::id::CommandId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 4,
        ]),
        gocode_domain::id::IdempotencyKey::new("projection-negative").unwrap(),
        1,
        gocode_domain::event::Actor::new("test").unwrap(),
        *draft.sensitivity(),
        draft.payload().clone(),
        1,
        gocode_domain::timestamp::Timestamp::from_unix_micros(1),
        gocode_domain::id::IntegrityDigest::from_bytes([5; 32]),
    );
    let projection = gocode_api::ReplayAggregateProjectionV1::from_conversation(
        &Conversation::replay(&[event]).unwrap(),
    )
    .unwrap();
    let bytes = projection.encoded_bytes();
    for malformed in [
        bytes[..bytes.len() - 1].to_vec(),
        {
            let mut value = bytes.to_vec();
            value[0] = 99;
            value
        },
        {
            let mut value = bytes.to_vec();
            value.push(0);
            value
        },
    ] {
        assert_eq!(
            gocode_api::UnauthenticatedReplayProjectionV1::decode_conversation_bytes(&malformed),
            Err(ReplayContractError::InvalidProjection)
        );
    }
    assert_eq!(
        gocode_api::UnauthenticatedReplayProjectionV1::decode_conversation_bytes(&vec![
            0;
            gocode_api::MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1
                + 1
        ],),
        Err(ReplayContractError::InvalidProjection)
    );
}

include!("replay_contract/projection_tail.rs");
