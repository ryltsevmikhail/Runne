use super::*;
use crate::canonical::RuntimeSessionAuthority;
use gocode_api::{ApiPrincipalId, DaemonInstanceId, StableRuntimeBinding};
use sha2::Sha256;

pub(super) const ID: [u8; 16] = [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1];
const ID_TEXT: &str = "018f2e3a-7000-7000-8000-000000000001";

pub(super) fn binding() -> gocode_api::RuntimeSessionBinding {
    gocode_api::RuntimeSessionBinding::new_with_sensitivity_label(
        StableRuntimeBinding::new(
            ID,
            ApiPrincipalId::new("owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000002".parse().unwrap(),
            "profile",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 3]),
        1,
        [5; 16],
        7,
        "internal",
        [6; 32],
    )
    .unwrap()
}

pub(super) fn scope() -> ReplayScope {
    ReplayScope::new(
        ReplayAggregateKind::Conversation,
        CanonicalId::parse(ID_TEXT).unwrap(),
    )
}

pub(super) fn wire(
    authority: &RuntimeSessionAuthority,
    binding: &gocode_api::RuntimeSessionBinding,
    scope: ReplayScope,
) -> gocode_api::ReplayRetentionBaselineWireV1 {
    let workspace = uuid::Uuid::parse_str("018f2e3a-7000-7000-8000-000000000006")
        .unwrap()
        .into_bytes();
    let projection_bytes = [
        vec![1],
        ID.to_vec(),
        workspace.to_vec(),
        vec![1, 0, 0, 0, 0, 0],
    ]
    .concat();
    let mut digest = Sha256::new();
    digest.update(b"gocode.replay.aggregate-projection");
    digest.update([0, 1, 2]);
    digest.update(ID);
    digest.update(u64::try_from(projection_bytes.len()).unwrap().to_be_bytes());
    digest.update(&projection_bytes);
    let stable = binding.stable();
    let fields = gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV1 {
        schema_version: 1,
        authority_id: *stable.authority_id(),
        principal_id: stable.principal_id().as_str().to_owned(),
        lineage_id: *stable.lineage_id().as_bytes(),
        runtime_session_binding_digest: binding.canonical_digest(),
        replay_scope_digest: gocode_api::canonical_aggregate_replay_scope_digest(
            gocode_api::ApiReplayAggregateKind::Conversation,
            &ID,
        ),
        aggregate_kind: gocode_api::ApiReplayAggregateKind::Conversation,
        aggregate_id: ID,
        sequence: 1,
        version: 1,
        baseline_global_position: 5,
        projection_codec: 1,
        projection_bytes,
        projection_digest: digest.finalize().into(),
        retained_floor: 6,
        captured_high_water: 6,
        retention_generation: 1,
        retention_witness: [8; 32],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        witness_mac: [0; 32],
    };
    let unsigned = gocode_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields);
    let mut fields = unsigned.to_unauthenticated_fields();
    fields.witness_mac =
        authority.replay_baseline_mac(fields.runtime_session_binding_digest, &unsigned);
    let _ = scope;
    gocode_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields)
}

#[test]
fn session_authority_accepts_exact_baseline_and_rejects_key_and_claim_tampering() {
    let binding = binding();
    let scope = scope();
    let authority = RuntimeSessionAuthority::from_local_session([9; 32])
        .bind_replay_session(Some(binding.clone()));
    let signed = wire(&authority, &binding, scope);
    assert_eq!(
        hex::encode(signed.to_unauthenticated_fields().witness_mac),
        "db577bf99de6e3d772b3a52d447a1a3ed0bb91c4d00032fff6f6df8e7259bfe8"
    );
    let verified = authority
        .verify_replay_retention_baseline(&signed, scope, 1_500)
        .unwrap();
    assert_eq!(verified.sequence(), 1);
    assert_eq!(
        verified.runtime_session_binding_digest(),
        &binding.canonical_digest()
    );
    assert_eq!(verified.retained_floor(), 6);
    let mut bad = signed.to_unauthenticated_fields();
    bad.projection_digest[0] ^= 1;
    assert!(matches!(
        authority.verify_replay_retention_baseline(
            &gocode_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(bad),
            scope,
            1_500
        ),
        Err(ReplayBaselineVerificationError::Unauthorized)
    ));
    assert!(matches!(
        RuntimeSessionAuthority::from_local_session([10; 32])
            .bind_replay_session(Some(binding.clone()))
            .verify_replay_retention_baseline(&signed, scope, 1_500),
        Err(ReplayBaselineVerificationError::Unauthorized)
    ));
    let wrong_binding = gocode_api::RuntimeSessionBinding::new_with_sensitivity_label(
        binding.stable().clone(),
        binding.ephemeral().daemon_instance_id(),
        1,
        [10; 16],
        7,
        "internal",
        *binding.certificate_sha256(),
    )
    .unwrap();
    assert!(matches!(
        RuntimeSessionAuthority::from_local_session([9; 32])
            .bind_replay_session(Some(wrong_binding))
            .verify_replay_retention_baseline(&signed, scope, 1_500),
        Err(ReplayBaselineVerificationError::Unauthorized)
    ));
}
