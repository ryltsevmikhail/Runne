use runne_api::{
    ApiReplayAggregateKind, ReplayPromotionProjectionV1, ReplayRetentionBaselineWireV2,
    UnauthenticatedReplayRetentionBaselineFieldsV2,
    validate_unauthenticated_replay_retention_baseline_v2,
};
use runne_domain::conversation::Conversation;
use runne_domain::event::{Actor, EventEnvelope};
use runne_domain::id::{
    AggregateId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
    WorkspaceId,
};
use runne_domain::task_run::{TaskRun, TaskRunEvent};
use runne_domain::timestamp::Timestamp;
use sha2::{Digest as _, Sha256};

#[path = "replay_baseline_v2_contract/transcript.rs"]
mod transcript;

const ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 1,
];

#[test]
fn v2_baseline_accepts_a_complete_promotion_projection() {
    let fields = valid_fields();
    let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields);

    let projection = validate_unauthenticated_replay_retention_baseline_v2(
        &wire,
        ApiReplayAggregateKind::Conversation,
        &ID,
    )
    .expect("complete promotion bytes must be structurally accepted");

    assert!(format!("{projection:?}").contains("redacted"));
}

#[test]
fn v2_baseline_accepts_a_complete_taskrun_promotion_projection() {
    let taskrun_id = TaskRunId::from_bytes(ID);
    let event = EventEnvelope::from_parts(
        EventId::from_bytes(uuid(6)),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        CommandId::from_bytes(uuid(8)),
        IdempotencyKey::new("baseline-v2-taskrun").unwrap(),
        1,
        Actor::new("test").unwrap(),
        runne_domain::event::Sensitivity::Public,
        TaskRunEvent::TaskRunCreated,
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([7; 32]),
    );
    let bytes = ReplayPromotionProjectionV1::encode_task_run(
        &TaskRun::replay(&[event]).unwrap().snapshot_v1(),
    )
    .unwrap();
    let mut fields = valid_fields();
    fields.aggregate_kind = ApiReplayAggregateKind::TaskRun;
    fields.promotion_projection_digest = promotion_digest(&bytes);
    fields.promotion_projection_bytes = bytes;
    let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields);

    assert!(
        validate_unauthenticated_replay_retention_baseline_v2(
            &wire,
            ApiReplayAggregateKind::TaskRun,
            &ID,
        )
        .is_ok()
    );
}

#[test]
fn v2_baseline_rejects_mutated_resumption_and_promotion_claims() {
    for mutate in [
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.head_event_id = [0; 16],
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| {
            value.head_integrity_digest = [0; 32]
        },
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| {
            value.retention_manifest_digest = [0; 32]
        },
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.sequence = 9,
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.version = 9,
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| {
            value.promotion_projection_digest = [0; 32]
        },
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| {
            value.promotion_projection_bytes.push(0)
        },
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.aggregate_id = uuid(9),
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.retention_generation = 0,
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| {
            value.expires_at_unix_ms = value.issued_at_unix_ms + 30_001
        },
    ] {
        let mut fields = valid_fields();
        mutate(&mut fields);
        let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields);
        assert!(
            validate_unauthenticated_replay_retention_baseline_v2(
                &wire,
                ApiReplayAggregateKind::Conversation,
                &ID,
            )
            .is_err()
        );
    }
    let mut oversize = valid_fields();
    oversize.promotion_projection_bytes = vec![0; 512 * 1024 + 1];
    assert!(
        validate_unauthenticated_replay_retention_baseline_v2(
            &ReplayRetentionBaselineWireV2::from_unauthenticated_fields(oversize),
            ApiReplayAggregateKind::Conversation,
            &ID,
        )
        .is_err()
    );
}

#[test]
fn v2_baseline_requires_retained_floor_not_to_exceed_baseline_position() {
    for (retained_floor, is_valid) in [(9, true), (10, true), (11, false)] {
        let mut fields = valid_fields();
        fields.captured_high_water = 12;
        fields.retained_floor = retained_floor;
        let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields);

        assert_eq!(
            validate_unauthenticated_replay_retention_baseline_v2(
                &wire,
                ApiReplayAggregateKind::Conversation,
                &ID,
            )
            .is_ok(),
            is_valid,
            "retained floor {retained_floor} must be {is_valid} for baseline position 10"
        );
    }
}

#[test]
fn v2_wire_parsing_exposes_no_authentication_or_promotion_authority() {
    let api = include_str!("../src/replay/baseline_v2_types.rs");

    assert!(api.contains("from_unauthenticated_fields"));
    assert!(!api.contains("pub fn authenticate"));
    assert!(!api.contains("pub fn promote"));
}

fn valid_fields() -> UnauthenticatedReplayRetentionBaselineFieldsV2 {
    let projection =
        ReplayPromotionProjectionV1::encode_conversation(&conversation().snapshot_v1(), &[])
            .unwrap();
    let digest = promotion_digest(&projection);
    UnauthenticatedReplayRetentionBaselineFieldsV2 {
        schema_version: 2,
        authority_id: uuid(2),
        principal_id: "local-owner".into(),
        lineage_id: uuid(3),
        runtime_session_binding_digest: [4; 32],
        replay_scope_digest: [5; 32],
        aggregate_kind: ApiReplayAggregateKind::Conversation,
        aggregate_id: ID,
        sequence: 1,
        version: 1,
        baseline_global_position: 10,
        head_event_id: uuid(6),
        head_integrity_digest: [7; 32],
        promotion_codec: 1,
        promotion_projection_bytes: projection,
        promotion_projection_digest: digest,
        retained_floor: 9,
        captured_high_water: 10,
        retention_generation: 1,
        retention_manifest_digest: [8; 32],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 31_000,
        witness_mac: [9; 32],
    }
}

fn conversation() -> Conversation {
    let id = ConversationId::from_bytes(ID);
    let command = Conversation::decide_create(id, WorkspaceId::from_bytes(uuid(7)));
    let event = EventEnvelope::from_parts(
        EventId::from_bytes(uuid(6)),
        command.aggregate_id().clone(),
        command.correlation_id().clone(),
        None,
        CommandId::from_bytes(uuid(8)),
        IdempotencyKey::new("baseline-v2").unwrap(),
        1,
        Actor::new("test").unwrap(),
        *command.sensitivity(),
        command.payload().clone(),
        1,
        Timestamp::from_unix_micros(1),
        IntegrityDigest::from_bytes([7; 32]),
    );
    Conversation::replay(&[event]).unwrap()
}

fn promotion_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.replay.promotion-projection");
    hasher.update([0, 1, bytes[5]]);
    hasher.update(ID);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn uuid(last: u8) -> [u8; 16] {
    [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, last,
    ]
}
