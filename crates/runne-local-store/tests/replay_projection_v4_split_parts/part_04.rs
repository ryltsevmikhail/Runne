#[test]
fn transition_atomically_persists_journal_projection_and_checkpoint() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let transition = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );

    assert_eq!(
        store
            .apply_replay_transition(&transition)
            .expect("apply transition"),
        ReplayApplyOutcome::Applied {
            database_generation: 2
        }
    );

    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("stored checkpoint");
    assert_eq!(checkpoint.cursor, "opaque.cursor.1");
    assert_eq!(checkpoint.generation, 3);
    assert_eq!(checkpoint.event_sequence, 1);
    assert_eq!(checkpoint.projection_revision, 1);
    assert_eq!(checkpoint.projection_digest, digest(projection));

    let stored = store
        .conversation_projection(&scope)
        .expect("read projection")
        .expect("stored projection");
    assert_eq!(stored.payload, projection);
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.event_sequence, 1);
    assert_eq!(stored.digest, digest(projection));
}

#[test]
fn exact_duplicate_is_already_applied_without_advancing_database_generation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let transition = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );
    store
        .apply_replay_transition(&transition)
        .expect("apply transition");

    assert_eq!(
        store
            .apply_replay_transition(&transition)
            .expect("apply exact duplicate"),
        ReplayApplyOutcome::AlreadyApplied {
            database_generation: 2
        }
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

#[test]
fn reset_replay_scope_is_atomic_and_preserves_other_scopes() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let affected = scope();
    let preserved = other_scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    for replay_scope in [&affected, &preserved] {
        store
            .apply_replay_transition(&transition(
                replay_scope,
                None,
                "event-1",
                "opaque.cursor.1",
                3,
                1,
                event,
                1,
                projection,
            ))
            .expect("apply replay scope");
    }
    let generation_before = store
        .diagnostics()
        .expect("diagnostics before reset")
        .database_generation;

    assert!(
        store
            .reset_replay_scope(&affected)
            .expect("reset affected scope")
    );

    assert_eq!(
        store
            .replay_checkpoint(&affected)
            .expect("read reset checkpoint"),
        None
    );
    assert_eq!(
        store
            .conversation_projection(&affected)
            .expect("read reset projection"),
        None
    );
    assert!(
        store
            .replay_checkpoint(&preserved)
            .expect("read preserved checkpoint")
            .is_some()
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics after reset")
            .database_generation,
        generation_before + 1
    );
    assert!(
        !store
            .reset_replay_scope(&affected)
            .expect("idempotent empty reset")
    );
}

#[test]
fn duplicate_rejects_changed_projection_bytes_digest_revision_or_json() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let original = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.1",
        3,
        1,
        event,
        1,
        projection,
    );
    store
        .apply_replay_transition(&original)
        .expect("apply original");

    let changed_projection =
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    let invalid_projection = br#"{"conversationId":"conversation-1""#;
    let conflicts = [
        ReplayTransition {
            projection_bytes: changed_projection,
            projection_digest: digest(changed_projection),
            ..original.clone()
        },
        ReplayTransition {
            projection_digest: "0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            ..original.clone()
        },
        ReplayTransition {
            projection_digest: "ABC".into(),
            ..original.clone()
        },
        ReplayTransition {
            projection_revision: 2,
            ..original.clone()
        },
        ReplayTransition {
            projection_bytes: invalid_projection,
            projection_digest: digest(invalid_projection),
            ..original
        },
    ];
    for conflict in &conflicts {
        let error = store
            .apply_replay_transition(conflict)
            .expect_err("changed duplicate projection must conflict");
        assert!(matches!(error, ReplayStoreError::EventIdentityConflict));
    }

    let stored = store
        .conversation_projection(&scope)
        .expect("read projection")
        .expect("stored projection");
    assert_eq!(stored.payload, projection);
    assert_eq!(stored.revision, 1);
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}
