#[test]
fn v20_rejects_released_v8_fixture_without_a_valid_complete_replay_history() {
    let temporary = tempfile::tempdir().unwrap();
    let path = {
        let daemon = temporary.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("released-v8.sqlite")
    };
    let conn = Connection::open(&path).unwrap();
    initialize_released_v8(&conn);
    conn.execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (1, ?1, 1, ?2, 0, 0)",
            params![TEST_ID, [0x24_u8; 16]],
        )
        .unwrap();
    conn.execute(
        "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
             VALUES (?1, 1, ?2, 1, 1, 0, 0, 1, NULL, ?3, x'01', x'02', x'03', ?4, ?2, 1, 1)",
        params![[0x24_u8; 16], TEST_ID, [0x25_u8; 16], [0x26_u8; 32]],
    )
    .unwrap();
    let before: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT event_id, aggregate_id, global_position, integrity_digest FROM events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    drop(conn);

    preflight_existing_file(&path).unwrap();
    let conn = open_managed_connection(&path, ConnectionMode::Writer).unwrap();

    assert!(apply_migrations(&conn).is_err());

    let after: (Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT event_id, aggregate_id, global_position, integrity_digest FROM events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        18
    );
}

#[test]
fn corrupt_v24_catalog_is_rejected_before_open() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    apply_migrations(&conn).unwrap();
    assert_eq!(CURRENT_SCHEMA_VERSION, 63);
    assert!(v63_matches(&conn, CURRENT_SCHEMA_VERSION).unwrap());
    conn.execute_batch("DROP TABLE provider_credential_operations;")
        .unwrap();
    assert!(classify_existing_connection(&conn).is_err());
}

#[test]
fn v23_to_v36_catalog_reopens_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let path = {
        let daemon = temporary.path().join("runne-daemon");
        std::fs::create_dir_all(&daemon).unwrap();
        daemon.join("v23-to-v24.sqlite")
    };
    let conn = Connection::open(&path).unwrap();
    initialize_released_v23(&conn);
    assert_eq!(current_schema_marker(&conn), 23);
    apply_migrations_internal(&conn, 27).unwrap();
    assert_eq!(current_schema_marker(&conn), 27);
    assert!(v27_matches(&conn, 27).unwrap());
    apply_migrations(&conn).unwrap();
    assert_eq!(current_schema_marker(&conn), CURRENT_SCHEMA_VERSION);
    drop(conn);
    let reopened = Connection::open(&path).unwrap();
    assert!(v63_matches(&reopened, CURRENT_SCHEMA_VERSION).unwrap());
}

#[test]
fn interrupted_v24_migration_recovers_from_v23() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    let transaction = conn.unchecked_transaction().unwrap();
    transaction.execute_batch(MIGRATION_V24).unwrap();
    assert!(
        transaction
            .execute_batch("CREATE TABLE interrupted_v24 (")
            .is_err()
    );
    transaction.rollback().unwrap();
    assert_eq!(current_schema_marker(&conn), 23);
    assert!(
        conn.execute("SELECT * FROM provider_credential_operations", [])
            .is_err()
    );
    apply_migrations(&conn).unwrap();
    assert_eq!(current_schema_marker(&conn), CURRENT_SCHEMA_VERSION);
    assert!(v63_matches(&conn, CURRENT_SCHEMA_VERSION).unwrap());
}
