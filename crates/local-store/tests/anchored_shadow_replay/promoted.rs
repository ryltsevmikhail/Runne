use super::*;

#[test]
#[allow(clippy::too_many_lines)]
fn promoted_shadow_routes_following_anchored_transition_to_selected_generation() {
    let directory = tempfile::tempdir().expect("temporary profile");
    let profile = [93; 32];
    let secure = DeterministicSecureStore::new(profile);
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open_anchored(&path, &secure, profile).expect("admitted");
    let replay_scope = scope("conversation");
    let legacy_event = br#"{"kind":"legacy"}"#;
    let legacy_projection = br#"{"messages":["legacy"]}"#;
    let legacy = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: None,
        event_id: "legacy-event",
        cursor: "legacy-cursor",
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
        .expect("legacy active");
    let legacy_checkpoint = store
        .authenticated_replay_checkpoint(&secure, &replay_scope)
        .expect("legacy checkpoint");
    let seed = gocode_local_store::ReplayBaselineSeed::for_local_store_test(
        &replay_scope,
        "session",
        "codec-v1",
        br#"{"messages":[]}"#,
        8,
        4,
        4_102_444_800_000,
    )
    .expect("bounded test seed");
    let shadow = store
        .begin_anchored_shadow_replay(&secure, &replay_scope, &seed)
        .expect("shadow persisted");
    let first_event = br#"{"kind":"first"}"#;
    let first_projection = br#"{"messages":["first"]}"#;
    let first = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: None,
        event_id: "event-9",
        cursor: "cursor-9",
        generation: 4,
        event_sequence: 9,
        event_bytes: first_event,
        event_digest: digest(first_event),
        projection_revision: 1,
        projection_bytes: first_projection,
        projection_digest: digest(first_projection),
    };
    assert!(matches!(
        store
            .apply_anchored_shadow_replay_transition(&secure, &shadow, &first)
            .expect("first suffix"),
        ReplayApplyOutcome::Applied { .. }
    ));
    store
        .seal_anchored_shadow_promotion(&secure, &replay_scope, &shadow, legacy_checkpoint.as_ref())
        .expect("seal exact shadow");
    store
        .commit_anchored_shadow_promotion(&secure, &replay_scope, &shadow)
        .expect("promote shadow");
    let checkpoint = store
        .authenticated_replay_checkpoint(&secure, &replay_scope)
        .expect("selected checkpoint")
        .expect("shadow checkpoint");
    let next_event = br#"{"kind":"next"}"#;
    let next_projection = br#"{"messages":["first","next"]}"#;
    let next = ReplayTransition {
        scope: &replay_scope,
        expected_checkpoint: Some(&checkpoint),
        event_id: "event-10",
        cursor: "cursor-10",
        generation: 4,
        event_sequence: 10,
        event_bytes: next_event,
        event_digest: digest(next_event),
        projection_revision: 2,
        projection_bytes: next_projection,
        projection_digest: digest(next_projection),
    };
    assert!(matches!(
        store
            .apply_anchored_replay_transition(&secure, &next)
            .expect("active shadow apply"),
        ReplayApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &replay_scope)
            .expect("selected projection")
            .expect("projection")
            .payload,
        next_projection
    );
    let before_reset = store
        .authenticated_replay_checkpoint(&secure, &replay_scope)
        .expect("checkpoint before reset")
        .expect("selected checkpoint before reset");
    assert!(matches!(
        store.reset_anchored_replay_scope(&secure, &replay_scope),
        Err(ReplayStoreError::PromotionConflict)
    ));
    assert_eq!(
        store
            .authenticated_conversation_projection(&secure, &replay_scope)
            .expect("selected projection remains")
            .expect("selected projection")
            .payload,
        next_projection
    );
    drop(store);
    let mut reopened = LocalStore::open_anchored(&path, &secure, profile).expect("reopen selected");
    assert_eq!(
        reopened
            .authenticated_replay_checkpoint(&secure, &replay_scope)
            .expect("reopened checkpoint")
            .expect("reopened selected checkpoint"),
        before_reset
    );
    assert_eq!(
        reopened
            .authenticated_conversation_projection(&secure, &replay_scope)
            .expect("reopened projection")
            .expect("reopened selected projection")
            .payload,
        next_projection
    );
}
