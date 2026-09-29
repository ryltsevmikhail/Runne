#[test]
fn v40_conversation_context_scope_reopens_and_rejects_drift() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("context-scope-v40.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    assert_eq!(schema_marker(&connection), 48);
    assert!(v48_matches(&connection, 48).unwrap());
    // The CHECK contract only admits the two closed scope values.
    connection
        .execute(
            "INSERT INTO conversation_context_scope
             (conversation_id, context_scope, recorded_at) VALUES (?1, 'workspace', 1)",
            [[7_u8; 16].as_slice()],
        )
        .unwrap();
    assert!(connection
        .execute(
            "INSERT INTO conversation_context_scope
             (conversation_id, context_scope, recorded_at) VALUES (?1, 'session', 1)",
            [[8_u8; 16].as_slice()],
        )
        .is_err());
    drop(connection);
    drop(open_managed_connection(&path, ConnectionMode::Writer).unwrap());

    // A current-marker database without the scope table is DDL drift.
    let drifted = Connection::open_in_memory().unwrap();
    apply_migrations(&drifted).unwrap();
    drifted
        .execute_batch("DROP TABLE conversation_context_scope;")
        .unwrap();
    assert!(!v48_matches(&drifted, 48).unwrap());
    assert!(classify_schema_version(&drifted).is_err());
}
