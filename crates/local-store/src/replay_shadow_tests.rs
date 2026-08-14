use crate::{ReplayBaselineSeed, ReplayScopeKey, scope_digest, valid_baseline_seed};

#[test]
fn baseline_validation_rejects_future_or_out_of_range_timestamps() {
    let scope = ReplayScopeKey {
        runtime_authority: "runtime".into(),
        principal: "principal".into(),
        lineage: "lineage".into(),
        scope: "scope".into(),
        binding_digest: "a".repeat(64),
    };
    let mut seed = ReplayBaselineSeed {
        session_binding: "a".repeat(64),
        promotion_codec: "codec".into(),
        payload: b"{}".to_vec(),
        scope_digest: scope_digest(&scope),
        authenticated_scope_digest: "b".repeat(64),
        schema_version: 2,
        head_event_id: "00000000-0000-7000-8000-000000000001".into(),
        head_integrity_digest: "c".repeat(64),
        retention_manifest_digest: "d".repeat(64),
        witness_digest: "e".repeat(64),
        retention_floor: 1,
        retention_high_water: 1,
        retention_generation: 1,
        issued_at: u64::MAX,
        baseline_sequence: 1,
        baseline_version: 1,
        baseline_position: 1,
        expires_at: u64::MAX,
    };
    assert!(!valid_baseline_seed(&scope, &seed, 10));
    seed.issued_at = 1;
    seed.expires_at = 11;
    assert!(valid_baseline_seed(&scope, &seed, 10));
}
