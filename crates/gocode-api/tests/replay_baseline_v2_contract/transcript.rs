use super::*;
use gocode_api::{
    REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1, REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2,
    replay_retention_baseline_v2_transcript,
};

#[test]
fn v2_transcript_binds_every_claim_except_the_mac() {
    let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(valid_fields());
    let expected = replay_retention_baseline_v2_transcript(&wire).unwrap();
    macro_rules! assert_bound {
        ($mutate:expr) => {{
            let mut changed = wire.to_unauthenticated_fields();
            $mutate(&mut changed);
            assert_ne!(
                expected,
                replay_retention_baseline_v2_transcript(
                    &ReplayRetentionBaselineWireV2::from_unauthenticated_fields(changed)
                )
                .unwrap()
            );
        }};
    }
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.schema_version ^= 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.authority_id[15] ^= 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.principal_id.push('x')
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.lineage_id[15] ^= 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value
            .runtime_session_binding_digest[0] ^=
            1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.replay_scope_digest
            [0] ^= 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.aggregate_kind =
            ApiReplayAggregateKind::TaskRun
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.aggregate_id[15] ^= 1
    );
    assert_bound!(|value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.sequence += 1);
    assert_bound!(|value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.version += 1);
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value
            .baseline_global_position +=
            1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.head_event_id[15] ^= 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.head_integrity_digest
            [0] ^= 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.promotion_codec += 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value
            .promotion_projection_bytes
            .push(0)
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value
            .promotion_projection_digest[0] ^=
            1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.retained_floor += 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.captured_high_water += 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.retention_generation +=
            1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value
            .retention_manifest_digest[0] ^=
            1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.issued_at_unix_ms += 1
    );
    assert_bound!(
        |value: &mut UnauthenticatedReplayRetentionBaselineFieldsV2| value.expires_at_unix_ms += 1
    );
}

#[test]
fn v2_transcript_ignores_only_mac_and_uses_a_distinct_key_domain() {
    let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(valid_fields());
    let expected = replay_retention_baseline_v2_transcript(&wire).unwrap();
    let mut changed = wire.to_unauthenticated_fields();
    changed.witness_mac[0] ^= 1;
    assert_eq!(
        expected,
        replay_retention_baseline_v2_transcript(
            &ReplayRetentionBaselineWireV2::from_unauthenticated_fields(changed)
        )
        .unwrap()
    );
    assert_ne!(
        REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V1,
        REPLAY_RETENTION_BASELINE_KEY_DOMAIN_V2
    );
}

#[test]
fn v2_transcript_rejects_unbounded_claims_before_allocating() {
    let mut fields = valid_fields();
    fields.principal_id = "x".repeat(257);
    assert!(
        replay_retention_baseline_v2_transcript(
            &ReplayRetentionBaselineWireV2::from_unauthenticated_fields(fields)
        )
        .is_err()
    );
}

#[test]
fn v2_transcript_has_a_stable_independent_digest() {
    let wire = ReplayRetentionBaselineWireV2::from_unauthenticated_fields(valid_fields());
    assert_eq!(
        hex_digest(&replay_retention_baseline_v2_transcript(&wire).unwrap()),
        "0b8cc7589b61dc006eaa8341e63c295420fa82faf5f6d9e0feb27fdce3bcef08",
    );
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
