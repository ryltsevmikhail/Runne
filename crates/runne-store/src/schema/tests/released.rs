fn initialize_released_v8(conn: &Connection) {
    initialize_v1(conn);
    let tx = conn.unchecked_transaction().unwrap();
    tx.execute_batch(MIGRATION_V2).unwrap();
    tx.execute("UPDATE events SET correlation_id = taskrun_id, correlation_type = 1, integrity_profile = 1", []).unwrap();
    tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])
        .unwrap();
    tx.commit().unwrap();
    for (version, migration) in [
        (3, MIGRATION_V3),
        (4, MIGRATION_V4),
        (5, MIGRATION_V5),
        (6, MIGRATION_V6),
        (7, MIGRATION_V7),
        (8, MIGRATION_V8),
    ] {
        let tx = conn.unchecked_transaction().unwrap();
        tx.execute_batch(migration).unwrap();
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [version],
        )
        .unwrap();
        tx.commit().unwrap();
    }
}

fn initialize_released_v23(conn: &Connection) {
    apply_migrations_through_v23_for_test(conn).unwrap();
}

#[test]
fn released_v8_upgrades_atomically_through_provider_v11() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v8(&conn);

    apply_migrations(&conn).unwrap();

    assert_eq!(CURRENT_SCHEMA_VERSION, 25);
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        25
    );
    assert!(
        conn.execute(
            "INSERT INTO consumption_intents VALUES (?1, 'key', 'Reserved', ?2, ?2, ?2)",
            params![[1_u8; 15].as_slice(), [2_u8; 32].as_slice()]
        )
        .is_err()
    );
    assert!(conn.execute("INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 6, 0, ?2, 'blob:test', 'store', 'producer', 0, 'sqlite')", params![[1_u8; 16].as_slice(), [2_u8; 32].as_slice()]).is_err());
}

#[test]
fn every_supported_schema_upgrades_to_v25() {
    for source in 8..=24 {
        let conn = Connection::open_in_memory().unwrap();
        initialize_supported_schema(&conn, source);
        assert_eq!(schema_marker(&conn), source);
        apply_migrations(&conn).unwrap();
        assert_eq!(schema_marker(&conn), 25, "source V{source}");
        assert!(v25_matches(&conn, 25).unwrap(), "source V{source}");
    }
}

fn initialize_supported_schema(conn: &Connection, version: i64) {
    match version {
        8 => initialize_released_v8(conn),
        9..=11 => {
            initialize_released_v8(conn);
            for (marker, migration) in [(9, MIGRATION_V9), (10, MIGRATION_V10), (11, MIGRATION_V11)]
            {
                if marker <= version {
                    apply_sql_migration(conn, marker, migration).unwrap();
                }
            }
        }
        12 => initialize_released_v12(conn),
        13 => initialize_released_v13(conn),
        14 => {
            initialize_released_v13(conn);
            provider_schema::apply_v14_migration(conn, |transaction| {
                install_missing_v12_fence_triggers(transaction)
            })
            .unwrap();
        }
        15 => apply_migrations_through_v15_for_test(conn).unwrap(),
        16 => apply_migrations_through_v16_for_test(conn).unwrap(),
        17 => apply_migrations_through_v17_for_test(conn).unwrap(),
        18 => apply_migrations_through_v18_for_test(conn).unwrap(),
        19 => apply_migrations_through_v19_for_test(conn).unwrap(),
        20..=24 => apply_migrations_internal(conn, version).unwrap(),
        _ => unreachable!("test controls supported schema versions"),
    }
}

fn initialize_released_v12(conn: &Connection) {
    initialize_released_v8(conn);
    for (marker, migration) in [(9, MIGRATION_V9), (10, MIGRATION_V10), (11, MIGRATION_V11)] {
        apply_sql_migration(conn, marker, migration).unwrap();
    }
    apply_v12(conn).unwrap();
}

fn initialize_released_v13(conn: &Connection) {
    initialize_released_v12(conn);
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive).unwrap();
    transaction.execute_batch(MIGRATION_V13).unwrap();
    install_missing_v12_fence_triggers(&transaction).unwrap();
    transaction
        .execute("INSERT INTO schema_version (version) VALUES (13)", [])
        .unwrap();
    transaction.commit().unwrap();
}

fn schema_marker(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
        row.get(0)
    })
    .unwrap()
}

#[test]
fn authority_head_persists_release_migration_fence() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    apply_migrations_internal(&conn, 24).unwrap();
    conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('release', 1, 1, 1, 1)", []).unwrap();
    conn.execute("INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest, created_at, updated_at) VALUES (?1, X'0101010101010101010101010101010101010101010101010101010101010101', 'release', 'WRITER_IDENTITY_MIGRATION_VERIFY', ?1, 'verify', 1, 1, 'PREPARED', ?2, ?3, 'VERIFY', ?4, ?5, 1, 1)", params![[18_u8; 16], [19_u8; 32], [20_u8; 16], [21_u8; 32], [17_u8; 32]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET release_migration_fence = 1, release_migration_binding_digest = ?1, release_migration_operation_id = ?2, release_migration_state = 'PENDING' WHERE provider_id = 'release'", params![[22_u8; 32], [18_u8; 16]]).is_err());
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET release_migration_fence = 1, release_migration_binding_digest = ?1, release_migration_operation_id = ?2, release_migration_state = 'PENDING', readiness_revision = 2 WHERE provider_id = 'release'", params![[17_u8; 32], [18_u8; 16]]).is_err());
    conn.execute("UPDATE provider_credential_authority_heads SET release_migration_fence = 1, release_migration_binding_digest = ?1, release_migration_operation_id = ?2, release_migration_state = 'PENDING', readiness_revision = 2, credential_fence = 2 WHERE provider_id = 'release'", params![[17_u8; 32], [18_u8; 16]]).unwrap();
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET release_migration_state = 'CLEARED' WHERE provider_id = 'release'", []).is_err());
    assert!(conn.execute("UPDATE provider_credential_authority_heads SET release_migration_state = 'VERIFIED' WHERE provider_id = 'release'", []).is_err());
    terminal_operation(&conn, 18);
    conn.execute("UPDATE provider_credential_authority_heads SET release_migration_state = 'VERIFIED', readiness_revision = 3 WHERE provider_id = 'release'", []).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET release_migration_state = 'CLEARED', readiness_revision = 4 WHERE provider_id = 'release'", []).unwrap();
}

#[test]
fn authority_head_update_without_release_migration_remains_allowed() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    apply_migrations(&conn).unwrap();
    conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version) VALUES ('head', 1, 1, 1, 1)", []).unwrap();
    conn.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision = 2 WHERE provider_id = 'head'", []).unwrap();
}

#[test]
fn authority_head_insert_cannot_bypass_release_migration_state_machine() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v23(&conn);
    apply_migrations(&conn).unwrap();
    assert!(conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version, release_migration_fence, release_migration_binding_digest, release_migration_state) VALUES ('insert-bypass', 1, 1, 1, 1, 1, ?1, 'VERIFIED')", [[17_u8; 32]]).is_err());
    assert!(conn.execute("INSERT INTO provider_credential_authority_heads (provider_id, lifecycle_revision, credential_fence, readiness_revision, next_credential_version, release_migration_fence, release_migration_state) VALUES ('insert-bypass', 1, 1, 1, 1, 1, 'CLEARED')", []).is_err());
}

#[test]
fn candidate_or_future_markers_are_rejected_without_mutation() {
    for marker in [9, 10, 11, 12] {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now'))); CREATE TABLE candidate_data (value TEXT NOT NULL);").unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [marker])
            .unwrap();
        conn.execute("INSERT INTO candidate_data VALUES ('unchanged')", [])
            .unwrap();
        let before: Vec<(String, String)> = conn
            .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<SqliteResult<_>>()
            .unwrap();

        assert!(
            apply_migrations(&conn).is_err(),
            "candidate marker V{marker} must fail closed"
        );

        let after: Vec<(String, String)> = conn
            .prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<SqliteResult<_>>()
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(
            conn.query_row("SELECT value FROM candidate_data", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "unchanged"
        );
    }
}

#[test]
fn tampered_candidate_intent_digest_is_rejected_not_recomputed() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));
             CREATE TABLE consumption_intents (intent_id BLOB PRIMARY KEY, idempotency_key TEXT NOT NULL, state TEXT NOT NULL, gate_head_snapshot_digest BLOB NOT NULL, target_artifact_digest BLOB NOT NULL, integrity_digest BLOB NOT NULL);",
        )
        .unwrap();
    conn.execute("INSERT INTO schema_version (version) VALUES (9)", [])
        .unwrap();
    conn.execute(
        "INSERT INTO consumption_intents VALUES (?1, 'legacy', 'Reserved', ?2, ?2, ?3)",
        params![
            [1_u8; 16].as_slice(),
            [2_u8; 32].as_slice(),
            [0xA5_u8; 32].as_slice()
        ],
    )
    .unwrap();

    assert!(apply_migrations(&conn).is_err());

    let digest: Vec<u8> = conn
        .query_row(
            "SELECT integrity_digest FROM consumption_intents",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(digest, vec![0xA5; 32]);
}

// Released V8 has no verification tables, so no released legacy intent
// digest exists to validate or rewrite. Candidate V9+ inputs reject above.

fn artifact_blob_prefix(table: &str) -> &'static str {
    match table {
        "migration_reports" => "report",
        "cutover_manifests" | "rollback_manifests" | "retirement_manifests" => "manifest",
        _ => unreachable!("test controls the table list"),
    }
}
