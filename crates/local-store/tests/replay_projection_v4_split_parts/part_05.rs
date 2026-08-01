#[test]
fn exact_duplicate_does_not_mask_a_corrupt_stored_projection() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let mut store = LocalStore::open(&path).expect("open store");
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect("apply transition");
    drop(store);
    let connection = Connection::open(&path).expect("open corruptible database");
    connection
        .execute_batch(
            "
            PRAGMA ignore_check_constraints = ON;
            UPDATE projections SET payload = x'7b';
            ",
        )
        .expect("corrupt projection");
    drop(connection);
    let mut store = LocalStore::open(&path).expect("reopen store");

    let error = store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect_err("corruption must stop duplicate application");
    assert!(matches!(error, ReplayStoreError::CorruptProjectionJson));
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}

#[test]
fn reused_event_id_with_different_identity_rolls_back() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    let first = transition(
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
    store.apply_replay_transition(&first).expect("apply first");
    let conflict = transition(
        &scope,
        None,
        "event-1",
        "opaque.cursor.changed",
        3,
        1,
        br#"{"eventId":"event-1","changed":true}"#,
        1,
        br#"{"conversationId":"conversation-1","messages":["changed"]}"#,
    );

    let error = store
        .apply_replay_transition(&conflict)
        .expect_err("identity conflict");
    assert!(matches!(error, ReplayStoreError::EventIdentityConflict));

    let digest_conflict = ReplayTransition {
        event_digest: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        ..transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        )
    };
    let error = store
        .apply_replay_transition(&digest_conflict)
        .expect_err("digest identity conflict");
    assert!(matches!(error, ReplayStoreError::EventIdentityConflict));

    assert_eq!(
        store
            .replay_checkpoint(&scope)
            .expect("read checkpoint")
            .expect("checkpoint")
            .cursor,
        "opaque.cursor.1"
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
fn rebound_scope_binding_is_not_reported_as_an_exact_duplicate() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect("apply transition");
    let rebound_scope = ReplayScopeKey {
        binding_digest: OTHER_BINDING_DIGEST.into(),
        ..scope
    };

    let error = store
        .apply_replay_transition(&transition(
            &rebound_scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect_err("binding mismatch");
    assert!(matches!(error, ReplayStoreError::BindingMismatch));
}

#[test]
fn transition_requires_the_exact_previous_checkpoint_and_contiguous_counters() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let event = br#"{"eventId":"event-1","sequence":1}"#;
    let projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            event,
            1,
            projection,
        ))
        .expect("apply first");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("checkpoint");

    let missing_expected = transition(
        &scope,
        None,
        "event-2",
        "opaque.cursor.2",
        3,
        2,
        br#"{"eventId":"event-2","sequence":2}"#,
        2,
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
    );
    assert!(matches!(
        store.apply_replay_transition(&missing_expected),
        Err(ReplayStoreError::CursorMismatch)
    ));

    let skipped_revision = ReplayTransition {
        projection_revision: 3,
        ..transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            2,
            br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
        )
    };
    assert!(matches!(
        store.apply_replay_transition(&skipped_revision),
        Err(ReplayStoreError::NonContiguousRevision)
    ));

    let skipped_sequence = ReplayTransition {
        event_sequence: 3,
        ..transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            2,
            br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
        )
    };
    assert!(matches!(
        store.apply_replay_transition(&skipped_sequence),
        Err(ReplayStoreError::NonContiguousSequence)
    ));
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        2
    );
}
