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
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(connection);
    assert_clean_preflight(&path);
    path
}

fn released_v8_database(name: &str) -> PathBuf {
    let path = canonical_current_database(name);
    let connection = Connection::open(&path).unwrap();
    let triggers = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='trigger'")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\";"))
            .unwrap();
    }
    connection
        .execute_batch(
            "DROP TABLE bootstrap_reservation_tombstones;
             DROP TABLE bootstrap_reservations;
             DROP TABLE bootstrap_last_observed_clock;
             DROP TABLE provider_credential_effect_bindings;
             DROP TABLE provider_credential_provisions;
             DROP TABLE provider_credential_clock_high_water;
             DROP TABLE provider_credential_versions;
             DROP TABLE provider_effect_starts;
             DROP TABLE provider_terminal_outbox;
             DROP TABLE provider_accounting_settlements;
             DROP TABLE provider_stream_journal;
             DROP TABLE provider_poll_flights;
             DROP TABLE provider_encryption_nonces;
             DROP TABLE provider_journal_key_refs;
             DROP TABLE provider_budget_reservations;
             DROP TABLE provider_execution_admissions;
             DROP TABLE provider_runtime_authority_state;
             DROP TABLE schema_upgrade_write_latch;
             DROP TABLE schema_upgrade_fence;
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
