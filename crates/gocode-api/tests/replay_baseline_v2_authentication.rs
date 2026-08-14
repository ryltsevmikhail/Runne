use gocode_api::{
    ApiReplayAggregateKind, ReplayPromotionProjectionV1, ReplayRetentionBaselineWireV2,
    UnauthenticatedAcceptedReplayProjectionFactsV2, UnauthenticatedAcceptedReplayProjectionV2,
    UnauthenticatedReplayRetentionBaselineFieldsV2,
};
use gocode_domain::conversation::Conversation;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    CommandId, ConversationId, EventId, EventLogLineageId, IdempotencyKey, IntegrityDigest,
    WorkspaceId,
};
use gocode_domain::timestamp::Timestamp;
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};

const ID: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];

#[test]
fn authenticated_v2_capability_rejects_a_wire_outside_its_bound_scope() {
    let binding = binding();
    let auth =
        gocode_api::ReplayBaselineV2Authenticator::from_native_rust_tcb([7; 32], binding.clone())
            .unwrap();
    let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(bound_fields(&binding));
    assert!(
        auth.verify_wire_v2(&wire, ApiReplayAggregateKind::TaskRun, ID, 1_000)
            .is_err()
    );
}

#[test]
fn authenticated_v2_capability_exposes_only_verified_semantic_promotion() {
    let binding = binding();
    let auth =
        gocode_api::ReplayBaselineV2Authenticator::from_native_rust_tcb([7; 32], binding.clone())
            .unwrap();
    let baseline = auth
        .verify_wire_v2(
            &signed_fields(&binding),
            ApiReplayAggregateKind::Conversation,
            ID,
            1_000,
        )
        .unwrap();
    assert_eq!(baseline.aggregate_id(), &ID);
    assert!(matches!(
        baseline.promotion_view(),
        gocode_api::ReplayPromotionProjectionViewV1::Conversation(_)
    ));
    assert!(format!("{baseline:?}").contains("redacted"));
}

#[test]
fn accepted_projection_rejects_a_baseline_minted_by_another_authority() {
    let binding = binding();
    let fields = signed_fields(&binding).to_unauthenticated_fields();
    let baseline =
        gocode_api::ReplayBaselineV2Authenticator::from_native_rust_tcb([7; 32], binding.clone())
            .unwrap()
            .verify_wire_v2(
                &ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields.clone()),
                ApiReplayAggregateKind::Conversation,
                ID,
                1_000,
            )
            .unwrap();
    let parsed = UnauthenticatedAcceptedReplayProjectionV2::new(
        gocode_api::UnauthenticatedReplayPromotionProjectionV1::decode(
            &fields.promotion_projection_bytes,
        )
        .unwrap(),
        UnauthenticatedAcceptedReplayProjectionFactsV2 {
            codec: 1,
            digest: fields.promotion_projection_digest,
            sequence: 1,
            version: 1,
            global_position: 10,
            head_event_id: fields.head_event_id,
            head_integrity_digest: fields.head_integrity_digest,
            captured_high_water: 10,
        },
    )
    .unwrap();
    assert!(
        gocode_api::ReplayBaselineV2Authenticator::from_native_rust_tcb([8; 32], binding)
            .unwrap()
            .authenticate_accepted_projection_v2(
                &baseline,
                parsed,
                gocode_api::ReplayAcceptedSuffixProofV2::Empty
            )
            .is_err()
    );
}

#[test]
fn checkpoint_capability_exposes_no_public_cursor_getter_or_serde() {
    let source = include_str!("../src/replay/accepted_v2_authenticated.rs");
    assert!(source.contains("with_local_persistence_cursor"));
    assert!(!source.contains("pub fn cursor"));
    assert!(!source.contains("Serialize for AuthenticatedReplayBaselineCheckpointV2"));
}

#[test]
fn checkpoint_capability_requires_the_authenticated_baseline_event_identity() {
    let binding = binding();
    let authenticator =
        gocode_api::ReplayBaselineV2Authenticator::from_native_rust_tcb([7; 32], binding.clone())
            .unwrap();
    let baseline = authenticator
        .verify_wire_v2(
            &signed_fields(&binding),
            ApiReplayAggregateKind::Conversation,
            ID,
            1_000,
        )
        .unwrap();
    let facts = gocode_api::UnauthenticatedReplayBaselineCheckpointFactsV2 {
        cursor: "gocode-replay-cursor-v1.00".into(),
        aggregate_kind: ApiReplayAggregateKind::Conversation,
        aggregate_id: ID,
        event_id: *baseline.head_event_id(),
        sequence: baseline.sequence(),
        global_position: baseline.baseline_global_position(),
    };
    assert!(
        authenticator
            .authenticate_resume_checkpoint_v2(&baseline, facts.clone())
            .is_ok()
    );
    let mut wrong_position = facts;
    wrong_position.global_position += 1;
    assert!(
        authenticator
            .authenticate_resume_checkpoint_v2(&baseline, wrong_position)
            .is_err()
    );
}

fn signed_fields(binding: &gocode_api::RuntimeSessionBinding) -> ReplayRetentionBaselineWireV2 {
    sign_fields(bound_fields(binding), binding)
}

fn sign_fields(
    mut fields: UnauthenticatedReplayRetentionBaselineFieldsV2,
    binding: &gocode_api::RuntimeSessionBinding,
) -> ReplayRetentionBaselineWireV2 {
    type H = Hmac<Sha256>;
    let mut derive = H::new_from_slice(&[7; 32]).unwrap();
    derive.update(gocode_api::REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2);
    derive.update(&binding.canonical_digest());
    let key: [u8; 32] = derive.finalize().into_bytes().into();
    let unsigned = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields.clone());
    let mut mac = H::new_from_slice(&key).unwrap();
    mac.update(&gocode_api::replay_retention_baseline_v2_transcript(&unsigned).unwrap());
    fields.witness_mac = mac.finalize().into_bytes().into();
    ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields)
}

fn bound_fields(
    binding: &gocode_api::RuntimeSessionBinding,
) -> UnauthenticatedReplayRetentionBaselineFieldsV2 {
    let snapshot = conversation().snapshot_v1();
    let bytes = ReplayPromotionProjectionV1::encode_conversation(&snapshot, &[]).unwrap();
    let mut digest = Sha256::new();
    digest.update(b"gocode.replay.promotion-projection");
    digest.update([0, 1, bytes[5]]);
    digest.update(ID);
    digest.update(&bytes);
    UnauthenticatedReplayRetentionBaselineFieldsV2 {
        schema_version: 2,
        authority_id: *binding.stable().authority_id(),
        principal_id: binding.stable().principal_id().as_str().to_owned(),
        lineage_id: *binding.stable().lineage_id().as_bytes(),
        runtime_session_binding_digest: binding.canonical_digest(),
        replay_scope_digest: gocode_api::canonical_aggregate_replay_scope_digest(
            ApiReplayAggregateKind::Conversation,
            &ID,
        ),
        aggregate_kind: ApiReplayAggregateKind::Conversation,
        aggregate_id: ID,
        sequence: 1,
        version: 1,
        baseline_global_position: 10,
        head_event_id: uuid(6),
        head_integrity_digest: [7; 32],
        promotion_codec: 1,
        promotion_projection_bytes: bytes,
        promotion_projection_digest: digest.finalize().into(),
        retained_floor: 9,
        captured_high_water: 10,
        retention_generation: 1,
        retention_manifest_digest: [8; 32],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 31_000,
        witness_mac: [0; 32],
    }
}

fn binding() -> gocode_api::RuntimeSessionBinding {
    let stable = gocode_api::StableRuntimeBinding::new(
        uuid(2),
        gocode_api::ApiPrincipalId::new("local-owner").unwrap(),
        EventLogLineageId::from_bytes(uuid(3)),
        "test",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    gocode_api::RuntimeSessionBinding::new(
        stable,
        gocode_api::DaemonInstanceId::from_bytes(uuid(4)),
        1,
        uuid(5),
        1,
        Sensitivity::Public,
        [3; 32],
    )
    .unwrap()
}

fn conversation() -> Conversation {
    let command = Conversation::decide_create(
        ConversationId::from_bytes(ID),
        WorkspaceId::from_bytes(uuid(7)),
    );
    let event = EventEnvelope::from_parts(
        EventId::from_bytes(uuid(6)),
        command.aggregate_id().clone(),
        command.correlation_id().clone(),
        None,
        CommandId::from_bytes(uuid(8)),
        IdempotencyKey::new("auth-v2").unwrap(),
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

fn uuid(last: u8) -> [u8; 16] {
    [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, last]
}

#[path = "replay_baseline_v2_authentication/binding.rs"]
mod binding_contract;
