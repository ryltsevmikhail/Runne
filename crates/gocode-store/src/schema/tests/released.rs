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

#[test]
fn released_v8_upgrades_atomically_through_provider_v11() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_released_v8(&conn);

    apply_migrations(&conn).unwrap();

    assert_eq!(CURRENT_SCHEMA_VERSION, 15);
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        15
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
