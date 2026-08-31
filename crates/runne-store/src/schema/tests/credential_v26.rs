#[test]
fn v25_to_v26_adds_empty_online_binding_table() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 25).unwrap();

    apply_migrations_internal(&connection, 26).unwrap();

    assert_eq!(current_schema_marker(&connection), 26);
    assert!(
        v22_process_registry_matches(&connection).unwrap(),
        "v22 process registry"
    );
    assert!(v26_predecessor_matches(&connection).unwrap(), "predecessor");
    assert!(v26_marker_matches(&connection).unwrap(), "marker");
    for table_name in [
        V26_ISSUANCE_EVIDENCE_TABLE,
        V26_CLAIM_PROVIDER_TABLE,
        V26_TABLE,
    ] {
        let table: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table_name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            normalize_v24_ddl(&table),
            v26_table_source(table_name),
            "{table_name}"
        );
    }
    for trigger in V26_TRIGGERS {
        assert!(
            v24_trigger_matches(&connection, trigger, v26_trigger_source(trigger)).unwrap(),
            "{trigger}"
        );
    }
    assert!(v26_matches(&connection, 26).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_online_credential_effect_bindings",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn v26_claim_provider_insert_requires_an_existing_admission() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations(&connection).unwrap();

    assert!(
        connection
        .execute(
            "INSERT INTO provider_online_dispatch_claim_providers (dispatch_attempt_id, provider_id)
             VALUES (?1, 'openai')",
            [vec![9_u8; 16]],
        )
        .is_err(),
        "a provider mapping without durable admission/evidence must be rejected"
    );
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_online_dispatch_claim_providers",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn online_issuance_guard_clears_on_success_error_and_unwind() {
    let directory = tempfile::tempdir().unwrap();
    let managed = open_test_shared_writer(&directory.path().join("guard.sqlite")).unwrap();
    let guard = managed.online_issuance_guard();
    let active = || {
        managed
            .query_row(
                "SELECT runne_online_issuance_guard(?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![vec![1_u8; 16], "openai", vec![2_u8; 16], 3_i64, 4_i64],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };

    let scope = guard.enable([1; 16], "openai", [2; 16], 3, 4).unwrap();
    assert_eq!(active(), 1);
    assert!(guard.enable([1; 16], "other", [2; 16], 3, 4).is_err());
    drop(scope);
    assert_eq!(active(), 0);

    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _scope = guard.enable([1; 16], "openai", [2; 16], 3, 4).unwrap();
            panic!("intentional issuance scope unwind");
        }))
        .is_err()
    );
    assert_eq!(active(), 0);
}

#[test]
fn v26_matcher_rejects_missing_extra_or_tampered_objects() {
    for statement in [
        "ALTER TABLE provider_online_credential_effect_bindings ADD COLUMN extra INTEGER",
        "ALTER TABLE provider_effect_starts ADD COLUMN extra INTEGER",
        "ALTER TABLE process_registry ADD COLUMN weakened_constraint INTEGER",
        "ALTER TABLE process_output ADD COLUMN extra INTEGER",
        "PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql, 'CHECK(state BETWEEN 1 AND 5)', 'CHECK(state BETWEEN 1 AND 6)') WHERE name='process_registry'; PRAGMA writable_schema=OFF;",
        "CREATE TABLE unexpected_v26_object (id INTEGER)",
        "CREATE INDEX unexpected_v26_index ON provider_effect_starts(state)",
        "CREATE TRIGGER unexpected_v26_trigger BEFORE INSERT ON provider_effect_starts BEGIN SELECT 1; END",
        "ALTER TABLE provider_credential_versions ADD COLUMN extra INTEGER",
        "DROP TRIGGER provider_online_dispatch_claim_provider_immutable",
        "DROP TRIGGER provider_online_dispatch_issuance_evidence_immutable",
        "DROP TRIGGER schema_v12_fence_provider_online_dispatch_claim_providers_insert",
        "DROP TRIGGER schema_v12_fence_provider_online_dispatch_issuance_evidence_insert",
        "DROP TRIGGER provider_online_credential_effect_binding_immutable",
        "DROP TRIGGER provider_credential_ticket_insert_issued",
        "DROP TRIGGER provider_credential_head_monotonic",
        "DROP TRIGGER bootstrap_clock_monotonic",
        "DROP TRIGGER global_command_id_from_command_receipts",
        "DROP TRIGGER aggregate_state_snapshots_bind_insert",
        "DROP INDEX provider_credential_one_active",
        "DROP INDEX idx_process_registry_owner; CREATE INDEX idx_process_registry_owner ON process_registry(process_id, principal_id)",
        "DELETE FROM schema_version WHERE version = 26",
    ] {
        let connection = Connection::open_in_memory().unwrap();
        initialize_released_v23(&connection);
        apply_migrations_internal(&connection, 26).unwrap();
        connection.execute_batch(statement).unwrap();
        assert!(!v26_matches(&connection, 26).unwrap(), "{statement}");
        assert!(
            classify_existing_connection(&connection).is_err(),
            "{statement}"
        );
    }
}

#[test]
fn v25_binary_rejects_v26_without_mutation() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_released_v23(&connection);
    apply_migrations_internal(&connection, 26).unwrap();
    let marker = current_schema_marker(&connection);
    assert!(!v25_matches(&connection, marker).unwrap());
    assert_eq!(current_schema_marker(&connection), marker);
}

#[test]
fn genuine_v19_fixture_history_remains_valid_through_v26() {
    let connection = Connection::open_in_memory().unwrap();
    initialize_supported_schema(&connection, 19);

    apply_migrations_internal(&connection, 26).unwrap();

    let marker: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(marker, (26, 1, 26, 351));
    assert!(v26_matches(&connection, 26).unwrap());
    assert!(classify_existing_connection(&connection).is_ok());
}

#[test]
fn file_backed_v25_preflight_rejects_v26_without_sidecars_or_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("frozen-v25.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations_internal(&connection, 25).unwrap();
    connection
        .execute(
            "INSERT INTO _daemon_info(key, value) VALUES ('v25-content', 'retained')",
            [],
        )
        .unwrap();
    apply_migrations_internal(&connection, 26).unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(connection);
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(&path, suffix);
        if sidecar.exists() {
            std::fs::remove_file(sidecar).unwrap();
        }
    }

    let bytes_before = std::fs::read(&path).unwrap();
    let read_only = Connection::open_with_flags(
        immutable_read_only_uri(&path).unwrap(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let catalog_before = catalog(&read_only);
    let content_before: String = read_only
        .query_row(
            "SELECT value FROM _daemon_info WHERE key='v25-content'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!v25_matches(&read_only, current_schema_marker(&read_only)).unwrap());
    drop(read_only);

    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
    let read_only = Connection::open_with_flags(
        immutable_read_only_uri(&path).unwrap(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    assert_eq!(catalog(&read_only), catalog_before);
    assert_eq!(
        read_only
            .query_row(
                "SELECT value FROM _daemon_info WHERE key='v25-content'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        content_before
    );
    assert!(!sidecar_path(&path, "-wal").exists());
    assert!(!sidecar_path(&path, "-shm").exists());
}

fn catalog(connection: &Connection) -> Vec<(String, String, String, Option<String>)> {
    connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<SqliteResult<Vec<_>>>()
        .unwrap()
}
