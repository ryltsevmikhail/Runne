fn checkpoint_and_close(connection: Connection) {
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    drop(connection);
}

fn immutable_read_only_connection(path: &Path) -> Connection {
    let text = path.to_str().unwrap();
    let mut uri = String::with_capacity(text.len() + 32);
    uri.push_str("file:");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;

            write!(&mut uri, "%{byte:02X}").unwrap();
        }
    }
    uri.push_str("?immutable=1");
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn assert_no_sidecars(path: &Path) {
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(
            !PathBuf::from(format!("{}{suffix}", path.display())).exists(),
            "fixture retained {suffix}"
        );
    }
}

fn assert_clean_preflight(path: &Path) {
    assert_no_sidecars(path);
    preflight_existing_file(path).unwrap();
}

fn canonical_current_database(name: &str) -> PathBuf {
    let path = current_database(name);
    let connection = open_with_pragmas(path.to_str().unwrap()).unwrap();
    apply_migrations(&connection).unwrap();
    checkpoint_and_close(connection);
    assert_clean_preflight(&path);
    path
}

fn released_v8_database(name: &str) -> PathBuf {
    let path = canonical_current_database(name);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER schema_v12_fence_aggregate_state_snapshots_insert;
             DROP TRIGGER schema_v12_fence_aggregate_state_snapshots_update;
             DROP TRIGGER schema_v12_fence_aggregate_state_snapshots_delete;
             DROP TRIGGER aggregate_state_snapshots_bind_insert;
             DROP TRIGGER aggregate_state_snapshots_bind_update;
             DROP TABLE aggregate_state_snapshots;
             DROP TABLE provider_effect_authorities;
             DROP TABLE provider_dispatch_attempts;
             DROP TABLE provider_prepared_requests;
             DROP TABLE schema_lineage;
             DROP TABLE consumption_intents;
             DROP TABLE verification_evidence;
             DELETE FROM schema_version WHERE version >= 9;",
        )
        .unwrap();
    checkpoint_and_close(connection);
    assert_clean_preflight(&path);
    path
}

fn apply_future_schema_marker(path: &Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [gocode_store::schema::CURRENT_SCHEMA_VERSION + 1],
        )
        .unwrap();
    checkpoint_and_close(connection);
}

fn assert_future_schema_marker(path: &Path) {
    let connection = immutable_read_only_connection(path);
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, gocode_store::schema::CURRENT_SCHEMA_VERSION + 1);
}

fn delete_schema_lineage(path: &Path) {
    let connection = Connection::open(path).unwrap();
    connection.execute("DELETE FROM schema_lineage", []).unwrap();
    checkpoint_and_close(connection);
}

fn apply_partial_v9_lineage_marker(path: &Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "INSERT INTO schema_version (version) VALUES (9);
             CREATE TABLE schema_lineage (
                 schema_version INTEGER PRIMARY KEY CHECK(schema_version = 9),
                 provenance TEXT NOT NULL CHECK(provenance = 'released-v8-to-strict-v9')
             );
             INSERT INTO schema_lineage (schema_version, provenance)
                 VALUES (9, 'released-v8-to-strict-v9');",
        )
        .unwrap();
    checkpoint_and_close(connection);
}
