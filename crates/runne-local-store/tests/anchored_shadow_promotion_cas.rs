#![cfg(feature = "test-support")]

use runne_local_store::{LocalStore, ReplayScopeKey, ReplayTransition};
use runne_secure_store::test_support::DeterministicSecureStore;
use sha2::{Digest, Sha256};

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn scope() -> ReplayScopeKey {
    ReplayScopeKey {
        runtime_authority: "runtime".into(),
        principal: "principal".into(),
        lineage: "lineage".into(),
        scope: "conversation".into(),
        binding_digest: digest(b"binding"),
    }
}

#[test]
fn legacy_write_between_promotion_phases_cannot_switch_stale_shadow() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [94; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let replay_scope = scope();
    let legacy_event = br#"{"kind":"legacy"}"#;
    let legacy_projection = br#"{"messages":["legacy"]}"#;
    let legacy = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: None,
        event_id: "legacy-1",
        cursor: "legacy-1",
        generation: 1,
        event_sequence: 1,
        event_bytes: legacy_event,
        event_digest: digest(legacy_event),
        projection_revision: 1,
        projection_bytes: legacy_projection,
        projection_digest: digest(legacy_projection),
    };
    store
        .apply_anchored_replay_transition(&secure, &legacy)
        .expect("legacy state");
    let checkpoint = store
        .authenticated_replay_checkpoint(&secure, &replay_scope)
        .expect("checkpoint")
        .expect("legacy");
    let seed = runne_local_store::ReplayBaselineSeed::for_local_store_test(
        &replay_scope,
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        8,
        4,
        4_102_444_800_000,
    )
    .expect("seed");
    let shadow = store
        .begin_anchored_shadow_replay(&secure, &replay_scope, &seed)
        .expect("shadow");
    let shadow_event = br#"{"kind":"shadow"}"#;
    let shadow_projection = br#"{"messages":["shadow"]}"#;
    let suffix = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: None,
        event_id: "shadow-9",
        cursor: "shadow-9",
        generation: 4,
        event_sequence: 9,
        event_bytes: shadow_event,
        event_digest: digest(shadow_event),
        projection_revision: 1,
        projection_bytes: shadow_projection,
        projection_digest: digest(shadow_projection),
    };
    store
        .apply_anchored_shadow_replay_transition(&secure, &shadow, &suffix)
        .expect("shadow suffix");
    store
        .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, Some(&checkpoint))
        .expect("seal");
    let changed_event = br#"{"kind":"changed"}"#;
    let changed_projection = br#"{"messages":["changed"]}"#;
    let changed = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: Some(&checkpoint),
        event_id: "legacy-2",
        cursor: "legacy-2",
        generation: 1,
        event_sequence: 2,
        event_bytes: changed_event,
        event_digest: digest(changed_event),
        projection_revision: 2,
        projection_bytes: changed_projection,
        projection_digest: digest(changed_projection),
    };
    store
        .apply_anchored_replay_transition(&secure, &changed)
        .expect("concurrent legacy write");

    assert!(
        store
            .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
            .is_err()
    );
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &replay_scope)
            .expect("legacy")
            .expect("projection")
            .payload,
        changed_projection
    );
}
