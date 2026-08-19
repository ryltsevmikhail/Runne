#![cfg(feature = "fixture-only")]

use runne_release_authority::{
    Digest, DurableFixtureThresholdContext, ThresholdFixtureStoreBinding,
    ThresholdVerificationState,
};
use std::collections::BTreeMap;
use std::fs;

#[test]
fn durable_threshold_context_reopens_the_exact_canonical_state() {
    let path = std::env::temp_dir().join(format!("runne-threshold-context-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let state = fixture_state();
    let binding =
        ThresholdFixtureStoreBinding::new(Digest::fixture([7; 32]), "fixture-v1", 1).unwrap();
    DurableFixtureThresholdContext::create(&path, binding.clone(), state.clone(), 1).unwrap();
    let reopened = DurableFixtureThresholdContext::reopen(&path, binding).unwrap();
    assert_eq!(reopened.state().unwrap(), state);
    fs::remove_file(path).unwrap();
}

fn fixture_state() -> ThresholdVerificationState {
    ThresholdVerificationState {
        versions: ["root", "targets", "snapshot", "timestamp"]
            .into_iter()
            .map(|role| (role.into(), 1))
            .collect(),
        rollback_floor: 1,
        revocation_floor: 1,
        frozen: false,
        generation: 1,
        root_keys: keyset("r", 1),
        targets_keys: keyset("t", 4),
        snapshot_key: ("snapshot".into(), [7; 32]),
        timestamp_key: ("timestamp".into(), [8; 32]),
        channel_policy_id: Some("fixture-channel-policy".into()),
        role_bodies: BTreeMap::new(),
        role_digests: BTreeMap::new(),
    }
}

fn keyset(prefix: &str, first: u8) -> BTreeMap<String, [u8; 32]> {
    (0..3)
        .map(|offset| (format!("{prefix}{}", offset + 1), [first + offset; 32]))
        .collect()
}
