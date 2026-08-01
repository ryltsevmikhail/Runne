#[test]
fn projection_reads_fail_closed_for_corrupt_json_digest_binding_and_revision() {
    for (label, mutation, expected) in [
        (
            "json",
            "PRAGMA ignore_check_constraints = ON;
             UPDATE projections SET payload = x'7b';",
            "corrupt",
        ),
        (
            "digest",
            "UPDATE projections
             SET projection_digest =
               '0000000000000000000000000000000000000000000000000000000000000000';",
            "digest",
        ),
        (
            "binding",
            "UPDATE projections
             SET binding_digest =
               '2222222222222222222222222222222222222222222222222222222222222222';",
            "binding",
        ),
        (
            "revision",
            "UPDATE projections SET projection_revision = projection_revision + 2;
             UPDATE replay_cursors SET projection_revision = projection_revision + 2;",
            "revision",
        ),
    ] {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join(format!("{label}.sqlite3"));
        let (store, scope) = create_applied_store(&path);
        drop(store);
        let connection = Connection::open(&path).expect("open corruptible database");
        connection
            .execute_batch(mutation)
            .expect("corrupt projection");
        drop(connection);
        let store = LocalStore::open(&path).expect("reopen store");

        let error = store
            .conversation_projection(&scope)
            .expect_err("corrupt projection must fail closed");
        match expected {
            "corrupt" => assert!(matches!(error, ReplayStoreError::CorruptProjectionJson)),
            "digest" => assert!(matches!(error, ReplayStoreError::ProjectionDigestMismatch)),
            "binding" => assert!(matches!(error, ReplayStoreError::BindingMismatch)),
            "revision" => assert!(matches!(error, ReplayStoreError::NonContiguousRevision)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn transition_rejects_empty_cursor_and_invalid_digests_before_mutation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let mut invalid_cursor = transition(
        &scope,
        None,
        "event-1",
        "",
        3,
        1,
        br#"{"eventId":"event-1"}"#,
        1,
        br#"{"conversationId":"conversation-1"}"#,
    );
    assert!(matches!(
        store.apply_replay_transition(&invalid_cursor),
        Err(ReplayStoreError::EmptyCursor)
    ));

    invalid_cursor.cursor = "opaque";
    invalid_cursor.event_digest = "ABC".into();
    assert!(matches!(
        store.apply_replay_transition(&invalid_cursor),
        Err(ReplayStoreError::InvalidDigest)
    ));

    let rebound_scope = ReplayScopeKey {
        binding_digest: OTHER_BINDING_DIGEST.into(),
        ..scope
    };
    assert!(
        store
            .replay_checkpoint(&rebound_scope)
            .expect("empty rebound scope")
            .is_none()
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        1
    );
}

#[test]
fn historical_concurrent_duplicate_is_confirmed_without_mutation() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let (mut store, scope) = create_applied_store(&path);
    let first_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("checkpoint")
        .expect("first checkpoint");
    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&first_checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            2,
            br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#,
        ))
        .expect("apply second");
    let generation_before = store
        .diagnostics()
        .expect("diagnostics")
        .database_generation;
    let event_bytes = br#"{"eventId":"event-1","sequence":1}"#;
    let event_digest = digest(event_bytes);
    let identity = AppliedReplayEvent {
        scope: &scope,
        event_id: "event-1",
        cursor: "opaque.cursor.1",
        generation: 3,
        event_sequence: 1,
        event_bytes,
        event_digest: &event_digest,
    };

    assert_eq!(
        store
            .confirm_replay_event_applied(&identity)
            .expect("confirm historical duplicate"),
        ReplayApplyOutcome::AlreadyApplied {
            database_generation: generation_before
        }
    );
    assert_eq!(
        store
            .diagnostics()
            .expect("diagnostics")
            .database_generation,
        generation_before
    );

    let changed = AppliedReplayEvent {
        cursor: "opaque.cursor.changed",
        ..identity
    };
    assert!(matches!(
        store.confirm_replay_event_applied(&changed),
        Err(ReplayStoreError::EventIdentityConflict)
    ));
}
