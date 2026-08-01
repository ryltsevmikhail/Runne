fn create_applied_store(path: &Path) -> (LocalStore, ReplayScopeKey) {
    let mut store = LocalStore::open(path).expect("open store");
    let scope = scope();
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            1,
            br#"{"conversationId":"conversation-1","messages":[]}"#,
        ))
        .expect("apply baseline");
    (store, scope)
}

#[test]
fn projection_revision_zero_and_independent_event_cadence_are_valid() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let initial_projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            0,
            initial_projection,
        ))
        .expect("apply revision-zero projection");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read checkpoint")
        .expect("checkpoint");
    assert_eq!(checkpoint.event_sequence, 1);
    assert_eq!(checkpoint.projection_revision, 0);

    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            0,
            initial_projection,
        ))
        .expect("apply event without projection change");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read second checkpoint")
        .expect("second checkpoint");
    assert_eq!(checkpoint.event_sequence, 2);
    assert_eq!(checkpoint.projection_revision, 0);

    let changed_projection =
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    let same_revision_change = transition(
        &scope,
        Some(&checkpoint),
        "event-3",
        "opaque.cursor.3",
        3,
        3,
        br#"{"eventId":"event-3","sequence":3}"#,
        0,
        changed_projection,
    );
    assert!(matches!(
        store.apply_replay_transition(&same_revision_change),
        Err(ReplayStoreError::NonContiguousRevision)
    ));

    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&checkpoint),
            "event-3",
            "opaque.cursor.3",
            3,
            3,
            br#"{"eventId":"event-3","sequence":3}"#,
            1,
            changed_projection,
        ))
        .expect("advance independent projection revision");
    let checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read third checkpoint")
        .expect("third checkpoint");
    assert_eq!(checkpoint.event_sequence, 3);
    assert_eq!(checkpoint.projection_revision, 1);
}

#[test]
fn corrupt_historical_event_digest_stops_reads_and_the_next_transition() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let mut store = LocalStore::open(&path).expect("open store");
    let scope = scope();
    let first_projection = br#"{"conversationId":"conversation-1","messages":[]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            None,
            "event-1",
            "opaque.cursor.1",
            3,
            1,
            br#"{"eventId":"event-1","sequence":1}"#,
            0,
            first_projection,
        ))
        .expect("apply first");
    let first_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read first checkpoint")
        .expect("first checkpoint");
    let second_projection =
        br#"{"conversationId":"conversation-1","messages":[{"id":"message-1"}]}"#;
    store
        .apply_replay_transition(&transition(
            &scope,
            Some(&first_checkpoint),
            "event-2",
            "opaque.cursor.2",
            3,
            2,
            br#"{"eventId":"event-2","sequence":2}"#,
            1,
            second_projection,
        ))
        .expect("apply second");
    let second_checkpoint = store
        .replay_checkpoint(&scope)
        .expect("read second checkpoint")
        .expect("second checkpoint");
    drop(store);

    let connection = Connection::open(&path).expect("open corruptible database");
    connection
        .execute(
            "UPDATE event_journal SET validated_event = ?1 WHERE event_sequence = 1",
            [b"{\"eventId\":\"event-1\",\"corrupt\":true}".as_slice()],
        )
        .expect("corrupt historical event bytes");
    drop(connection);

    let mut store = LocalStore::open(&path).expect("reopen store");
    assert!(matches!(
        store.replay_checkpoint(&scope),
        Err(ReplayStoreError::EventDigestMismatch)
    ));
    assert!(matches!(
        store.conversation_projection(&scope),
        Err(ReplayStoreError::EventDigestMismatch)
    ));
    let error = store
        .apply_replay_transition(&transition(
            &scope,
            Some(&second_checkpoint),
            "event-3",
            "opaque.cursor.3",
            3,
            3,
            br#"{"eventId":"event-3","sequence":3}"#,
            1,
            second_projection,
        ))
        .expect_err("historical corruption must stop cursor advance");
    assert!(matches!(error, ReplayStoreError::EventDigestMismatch));
    drop(store);

    let connection = Connection::open(path).expect("inspect preserved state");
    let (journal_count, cursor, database_generation): (i64, String, i64) = connection
        .query_row(
            "
            SELECT COUNT(*), replay_cursors.applied_cursor, meta.db_generation
            FROM event_journal
            CROSS JOIN replay_cursors
            CROSS JOIN meta
            WHERE meta.singleton = 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read preserved state");
    assert_eq!(journal_count, 2);
    assert_eq!(cursor, "opaque.cursor.2");
    assert_eq!(database_generation, 3);
}

#[test]
fn corrupt_stored_event_digest_shape_fails_closed() {
    let directory = tempfile::tempdir().expect("temp directory");
    let path = directory.path().join("profile.sqlite3");
    let (store, scope) = create_applied_store(&path);
    drop(store);
    let connection = Connection::open(&path).expect("open corruptible database");
    connection
        .execute_batch(
            "
            PRAGMA ignore_check_constraints = ON;
            UPDATE event_journal SET event_digest = 'ABC' WHERE event_sequence = 1;
            ",
        )
        .expect("corrupt event digest shape");
    drop(connection);

    let store = LocalStore::open(&path).expect("reopen store");
    assert!(matches!(
        store.replay_checkpoint(&scope),
        Err(ReplayStoreError::InvalidDigest)
    ));
}
