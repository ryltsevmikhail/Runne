use gocode_api::{
    ApiReplayAggregateKind, ApiReplayBindingId, ApiReplayBindingV1, ApiReplayEventSchema,
    LocalSessionContractError, ReplayContractError, RetentionManifest, RuntimeSessionBinding,
    StableRuntimeBinding,
};
use gocode_domain::event::Sensitivity;
use gocode_domain::id::EventLogLineageId;
use gocode_domain::replay::ReplayScope;

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
