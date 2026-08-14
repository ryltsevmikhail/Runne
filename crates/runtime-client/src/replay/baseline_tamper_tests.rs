use super::ReplayBaselineVerificationError;
use super::baseline_tests::{binding, scope, wire};
use crate::canonical::RuntimeSessionAuthority;

struct BaselineFixture {
    authority: RuntimeSessionAuthority,
    scope: super::ReplayScope,
    signed: gocode_api::ReplayRetentionBaselineWireV1,
}

fn fixture() -> BaselineFixture {
    let binding = binding();
    let scope = scope();
    let authority = RuntimeSessionAuthority::from_local_session([9; 32])
        .bind_replay_session(Some(binding.clone()));
    let signed = wire(&authority, &binding, scope);
    BaselineFixture {
        authority,
        scope,
        signed,
    }
}

fn rejects(fixture: &BaselineFixture, mutate: impl FnOnce(&mut Fields)) {
    let mut fields = fixture.signed.to_unauthenticated_fields();
    mutate(&mut fields);
    let tampered =
        gocode_api::ReplayRetentionBaselineWireV1::from_unauthenticated_fields(fields.clone());
    assert_ne!(
        fixture
            .authority
            .replay_baseline_mac(fields.runtime_session_binding_digest, &tampered),
        fields.witness_mac,
    );
    assert!(matches!(
        fixture
            .authority
            .verify_replay_retention_baseline(&tampered, fixture.scope, 1_500),
        Err(ReplayBaselineVerificationError::Unauthorized)
    ));
}

type Fields = gocode_api::UnauthenticatedReplayRetentionBaselineFieldsV1;

#[test]
fn verifier_mac_binds_schema_identity_and_scope_claims() {
    let fixture = fixture();
    rejects(&fixture, |v: &mut Fields| v.schema_version = 2);
    rejects(&fixture, |v: &mut Fields| v.authority_id[0] ^= 1);
    rejects(&fixture, |v: &mut Fields| v.principal_id.push('x'));
    rejects(&fixture, |v: &mut Fields| v.lineage_id[0] ^= 1);
    rejects(&fixture, |v: &mut Fields| {
        v.runtime_session_binding_digest[0] ^= 1;
    });
    rejects(&fixture, |v: &mut Fields| v.replay_scope_digest[0] ^= 1);
    rejects(&fixture, |v: &mut Fields| {
        v.aggregate_kind = gocode_api::ApiReplayAggregateKind::TaskRun;
    });
    rejects(&fixture, |v: &mut Fields| v.aggregate_id[0] ^= 1);
}

#[test]
fn verifier_mac_binds_projection_and_position_claims() {
    let fixture = fixture();
    rejects(&fixture, |v: &mut Fields| v.sequence = 2);
    rejects(&fixture, |v: &mut Fields| v.version = 2);
    rejects(&fixture, |v: &mut Fields| v.baseline_global_position = 4);
    rejects(&fixture, |v: &mut Fields| v.projection_codec = 2);
    rejects(&fixture, |v: &mut Fields| v.projection_bytes[0] ^= 1);
    rejects(&fixture, |v: &mut Fields| v.projection_digest[0] ^= 1);
    rejects(&fixture, |v: &mut Fields| v.retained_floor = 5);
    rejects(&fixture, |v: &mut Fields| v.captured_high_water = 7);
}

#[test]
fn verifier_mac_binds_retention_witness_time_and_mac_claims() {
    let fixture = fixture();
    rejects(&fixture, |v: &mut Fields| v.retention_generation = 2);
    rejects(&fixture, |v: &mut Fields| v.retention_witness[0] ^= 1);
    rejects(&fixture, |v: &mut Fields| v.issued_at_unix_ms = 1_001);
    rejects(&fixture, |v: &mut Fields| v.expires_at_unix_ms = 1_999);
    rejects(&fixture, |v: &mut Fields| v.witness_mac[0] ^= 1);
}

#[test]
fn baseline_promotion_and_session_binding_remain_crate_private() {
    let verifier = include_str!("baseline.rs");
    let authority = include_str!("../canonical/types.rs");
    assert!(verifier.contains("pub(crate) fn verify_replay_retention_baseline"));
    assert!(!verifier.contains("pub fn verify_replay_retention_baseline"));
    assert!(!verifier.contains("Serialize"));
    assert!(!verifier.contains("Deserialize"));
    assert!(authority.contains("pub(crate) fn bind_replay_session"));
    assert!(!authority.contains("pub fn bind_replay_session"));
    assert!(!authority.contains("pub fn authority_bytes"));
}
