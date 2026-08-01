#[test]
fn response_corruption_fails_closed_without_mutation() {
    for (name, sql) in [
        (
            "codec-version",
            "UPDATE session_bindings SET response_codec_version = 2",
        ),
        (
            "trailing-whitespace",
            "UPDATE session_bindings SET response_snapshot = CAST(response_snapshot || X'20' AS BLOB)",
        ),
        (
            "noncanonical-order",
            "UPDATE session_bindings SET response_snapshot = X'7b226964223a2273657373696f6e2d61222c226469726563746f7279223a222f746d70222c2270726f6a6563744944223a2270726f6a6563742d61222c22736c7567223a2261222c2274696d65223a7b2263726561746564223a312c2275706461746564223a317d2c227469746c65223a2241207469746c65222c2276657273696f6e223a22312e30227d'",
        ),
        (
            "invalid-schema",
            "UPDATE session_bindings SET response_snapshot = X'7b7d'",
        ),
        (
            "truncated",
            "UPDATE session_bindings SET response_snapshot = X'7b'",
        ),
        (
            "oversized",
            "PRAGMA ignore_check_constraints = ON; UPDATE session_bindings SET response_snapshot = zeroblob(65537); PRAGMA ignore_check_constraints = OFF;",
        ),
    ] {
        let path = db_path();
        let store = SqliteSessionBindingStore::open(&path).unwrap();
        let key = key();
        let value = context();
        let expected = response();
        store.ensure_pending(&key, &value).unwrap();
        store
            .commit(&key, value.conversation_id, &expected)
            .unwrap();
        raw(&path).execute_batch(sql).unwrap();
        let before = full_row(&path);
        let state_before = singleton(&path);
        assert_eq!(
            store.lookup(&key),
            Err(BindingError::SerializationFailed),
            "{name}"
        );
        assert_eq!(
            store.commit(&key, value.conversation_id, &expected),
            Err(BindingError::SerializationFailed),
            "{name}"
        );
        assert_eq!(full_row(&path), before, "{name}");
        assert_eq!(singleton(&path), state_before, "{name}");
    }
}

#[test]
fn commit_different_valid_response_preserves_existing_bytes() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open(&path).unwrap();
    let key = key();
    let value = context();
    let first = response();
    store.ensure_pending(&key, &value).unwrap();
    store.commit(&key, value.conversation_id, &first).unwrap();
    let other = OpenCodeSessionInfo::from_json(serde_json::json!({"id":"session-a","slug":"b","projectID":"project-a","directory":"/tmp","title":"A title","version":"1.0","time":{"created":1,"updated":1}}), &jsonschema::JSONSchema::options().with_draft(jsonschema::Draft::Draft202012).compile(&serde_json::from_str(include_str!("../../../../docs/schemas/session-info-v1.schema.json")).unwrap()).unwrap()).unwrap();
    let before: Vec<u8> = raw(&path)
        .query_row(
            "SELECT response_snapshot FROM session_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        store.commit(&key, value.conversation_id, &other),
        Err(BindingError::Conflict(key))
    );
    let after: Vec<u8> = raw(&path)
        .query_row(
            "SELECT response_snapshot FROM session_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn frozen_clock_allocates_strictly_increasing_timestamps_and_overflow_inserts_nothing() {
    let path = db_path();
    let store = SqliteSessionBindingStore::open_with_clock(
        &path,
        Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(10).unwrap()))),
    )
    .unwrap();
    let first = key();
    let second = another_key(2);
    store.ensure_pending(&first, &context()).unwrap();
    store.ensure_pending(&second, &another_context(4)).unwrap();
    let times: Vec<i64> = raw(&path)
        .prepare("SELECT created_at FROM session_bindings ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(times, vec![10, 11]);
    raw(&path)
        .execute(
            "UPDATE gocode_session_binding_state SET last_created_at = ?1",
            [i64::MAX],
        )
        .unwrap();
    assert_eq!(
        store.ensure_pending(&another_key(3), &another_context(5)),
        Err(BindingError::StorageFailure)
    );
    assert_eq!(rows(&path), 2);
}

#[test]
fn independent_connections_race_same_context_to_created_and_already_pending() {
    let path = db_path();
    let barrier = Arc::new(Barrier::new(2));
    let key = key();
    let value = context();
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let barrier = barrier.clone();
            let key = key.clone();
            let value = value.clone();
            let store = SqliteSessionBindingStore::open(&path).unwrap();
            thread::spawn(move || {
                barrier.wait();
                store.ensure_pending(&key, &value)
            })
        })
        .collect();
    let mut outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    outcomes.sort_by_key(|outcome| match outcome {
        EnsurePendingResult::Created => 0,
        EnsurePendingResult::AlreadyPending => 1,
        EnsurePendingResult::AlreadyCommitted => 2,
    });
    assert_eq!(
        outcomes,
        vec![
            EnsurePendingResult::Created,
            EnsurePendingResult::AlreadyPending
        ]
    );
    assert_eq!(rows(&path), 1);
    assert_eq!(
        SqliteSessionBindingStore::open(&path).unwrap().lookup(&key),
        Ok(Some(SessionBindingStatus::Pending { context: value }))
    );
}

#[test]
fn independent_connections_race_different_context_to_created_and_conflict() {
    let path = db_path();
    let barrier = Arc::new(Barrier::new(2));
    let key = key();
    let first = context();
    let mut second = first.clone();
    second.title = None;
    let handles: Vec<_> = [first.clone(), second]
        .into_iter()
        .map(|value| {
            let barrier = barrier.clone();
            let key = key.clone();
            let store = SqliteSessionBindingStore::open(&path).unwrap();
            thread::spawn(move || {
                barrier.wait();
                store.ensure_pending(&key, &value)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(outcomes.contains(&Ok(EnsurePendingResult::Created)));
    assert!(outcomes.contains(&Err(BindingError::Conflict(key.clone()))));
    assert_eq!(rows(&path), 1);
}

#[test]
fn independent_connections_race_different_keys_with_frozen_clock() {
    let path = db_path();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [(key(), context()), (another_key(2), another_context(4))]
        .into_iter()
        .map(|(key, value)| {
            let barrier = barrier.clone();
            let store = SqliteSessionBindingStore::open_with_clock(
                &path,
                Arc::new(FixedClock(Ok(NonNegativeUnixMillis::new(10).unwrap()))),
            )
            .unwrap();
            thread::spawn(move || {
                barrier.wait();
                store.ensure_pending(&key, &value)
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), Ok(EnsurePendingResult::Created));
    }
    let created: Vec<i64> = raw(&path)
        .prepare("SELECT created_at FROM session_bindings ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(created, vec![10, 11]);
    assert_eq!(rows(&path), 2);
    assert_eq!(singleton(&path), 11);
}

#[test]
fn future_namespaced_schema_version_is_rejected_on_open() {
    let path = db_path();
    drop(SqliteSessionBindingStore::open(&path).unwrap());
    raw(&path)
        .execute(
            "INSERT INTO gocode_session_binding_schema_version(version) VALUES (2)",
            [],
        )
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn missing_binding_table_is_rejected_on_open() {
    let path = db_path();
    drop(SqliteSessionBindingStore::open(&path).unwrap());
    raw(&path)
        .execute_batch("DROP TABLE session_bindings;")
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}

#[test]
fn missing_recovery_index_is_rejected_on_open() {
    let path = db_path();
    drop(SqliteSessionBindingStore::open(&path).unwrap());
    raw(&path)
        .execute_batch("DROP INDEX idx_session_bindings_recovery;")
        .unwrap();
    assert!(matches!(
        SqliteSessionBindingStore::open(&path),
        Err(BindingError::StorageFailure)
    ));
}
