use super::super::*;

#[test]
fn selected_shadow_confirms_its_exact_duplicate_not_a_legacy_collision() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [120; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let replay_scope = scope();
    let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
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
    let event = br#"{"kind":"shadow"}"#;
    let projection = br#"{"messages":["shadow"]}"#;
    let transition = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: None,
        event_id: "same-id",
        cursor: "shadow-cursor",
        generation: 4,
        event_sequence: 9,
        event_bytes: event,
        event_digest: format!("{:x}", Sha256::digest(event)),
        projection_revision: 1,
        projection_bytes: projection,
        projection_digest: format!("{:x}", Sha256::digest(projection)),
    };
    store
        .apply_anchored_shadow_replay_transition(&secure, &shadow, &transition)
        .expect("suffix");
    store
        .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, None)
        .expect("seal");
    store
        .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
        .expect("promote");
    let applied = AppliedReplayEvent {
        scope: &replay_scope,
        event_id: "same-id",
        cursor: "shadow-cursor",
        generation: 4,
        event_sequence: 9,
        event_bytes: event,
        event_digest: &transition.event_digest,
    };
    assert!(matches!(
        store.authenticated_confirm_replay_event_applied(&secure, &applied),
        Ok(gocode_local_store::ReplayApplyOutcome::AlreadyApplied { .. })
    ));
    let legacy = AppliedReplayEvent {
        cursor: "legacy-cursor",
        ..applied
    };
    assert!(matches!(
        store.authenticated_confirm_replay_event_applied(&secure, &legacy),
        Err(ReplayStoreError::EventIdentityConflict)
    ));
}
