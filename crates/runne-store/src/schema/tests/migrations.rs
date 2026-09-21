#[test]
fn v20_rejects_legacy_event_without_a_valid_complete_replay_history() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_v1(&conn);
    conn.execute(
        "INSERT INTO task_run_streams
             (taskrun_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (?1, 1, ?1, 0, 0)",
        params![TEST_ID],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO events
             (event_id, taskrun_id, sequence, global_position, timestamp,
              aggregate_type, sensitivity, schema_version, causation_id,
              command_id, idempotency_key, actor, payload, integrity_digest)
             VALUES (?1, ?1, 1, 1, 0, 1, 0, 1, NULL, ?1, x'01', x'02', x'03', zeroblob(32))",
        params![TEST_ID],
    )
    .unwrap();

    assert!(apply_migrations(&conn).is_err());
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        18,
    );
    let snapshot_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'aggregate_state_snapshots')",
        [], |row| row.get(0),
    ).unwrap();
    assert!(!snapshot_table);

    let (
        aggregate_id,
        correlation_id,
        correlation_type,
        integrity_profile,
        global_position,
        integrity_digest,
    ): (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>) = conn
        .query_row(
            "SELECT aggregate_id, correlation_id, correlation_type, integrity_profile,
                        global_position, integrity_digest
                 FROM events",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(aggregate_id, TEST_ID);
    assert_eq!(correlation_id, TEST_ID);
    assert_eq!(correlation_type, 1);
    assert_eq!(integrity_profile, 1);
    assert_eq!(global_position, 1);
    assert_eq!(integrity_digest, vec![0; 32]);

    let stream_type: i64 = conn
        .query_row(
            "SELECT aggregate_type FROM aggregate_streams WHERE aggregate_id = ?1",
            params![TEST_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stream_type, 1);
}

#[test]
fn test_failed_v2_migration_rolls_back_and_can_retry() {
    let conn = Connection::open_in_memory().unwrap();
    initialize_v1(&conn);
    conn.execute_batch("CREATE TABLE aggregate_streams (taskrun_id BLOB PRIMARY KEY)")
        .unwrap();

    assert!(apply_migrations(&conn).is_err());

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 1);
    let correlation_column_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'correlation_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(correlation_column_count, 0);

    conn.execute_batch("DROP TABLE aggregate_streams").unwrap();
    apply_migrations(&conn).unwrap();

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'aggregate_streams'",
                [],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(table_count, 1);
}

#[test]
fn schema_v6_adds_migration_tables_with_cycle_lineage_atomically() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations(&conn).unwrap();

    assert_eq!(CURRENT_SCHEMA_VERSION, 40);
    for table in [
        "migration_plans",
        "migration_transitions",
        "migration_evidence",
        "routing_snapshots",
        "routing_head",
        "runtime_bindings",
        "routing_dispatch_intents",
        "migration_reports",
        "cutover_manifests",
        "rollback_manifests",
        "retirement_manifests",
        "migration_receipts",
        "migration_audit",
    ] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "missing migration table {table}");
    }
    for table in [
        "migration_reports",
        "cutover_manifests",
        "rollback_manifests",
        "retirement_manifests",
    ] {
        let cycle_column_count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'cycle_id'"
                ),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cycle_column_count, 1, "missing cycle lineage on {table}");
    }
}

#[test]
fn schema_v7_adds_atomic_pre_effect_tables_together() {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations(&conn).unwrap();

    for table in [
        "security_dispatch_intents",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_audit_pre_effect",
        "security_permit_claims",
    ] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "missing atomic pre-effect table {table}");
    }
}

#[test]
fn schema_v6_backfills_existing_artifacts_without_changing_identity_or_bytes() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
             CREATE TABLE migration_plans (
                 plan_id TEXT PRIMARY KEY,
                 cycle_id TEXT NOT NULL UNIQUE
             );
             INSERT INTO migration_plans VALUES ('plan-1', 'cycle-1');
             INSERT INTO migration_plans VALUES ('parent-1', 'parent-cycle-1');
             CREATE TABLE migration_reports (
                 report_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 report_kind INTEGER NOT NULL,
                 report_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE cutover_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE rollback_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 parent_plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE retirement_manifests (
                 manifest_id BLOB PRIMARY KEY,
                 plan_id TEXT NOT NULL REFERENCES migration_plans(plan_id),
                 manifest_blob BLOB NOT NULL,
                 created_at INTEGER NOT NULL
             );
             INSERT INTO migration_reports VALUES (zeroblob(32), 'plan-1', 1, x'0102', 10);
             INSERT INTO cutover_manifests VALUES (randomblob(32), 'plan-1', x'0304', 11);
             INSERT INTO rollback_manifests
                 VALUES (randomblob(32), 'plan-1', 'parent-1', x'0506', 12);
             INSERT INTO retirement_manifests VALUES (randomblob(32), 'plan-1', x'0708', 13);",
    )
    .unwrap();

    conn.execute_batch(MIGRATION_V6).unwrap();

    for (table, expected_blob) in [
        ("migration_reports", vec![1_u8, 2]),
        ("cutover_manifests", vec![3_u8, 4]),
        ("rollback_manifests", vec![5_u8, 6]),
        ("retirement_manifests", vec![7_u8, 8]),
    ] {
        let (cycle_id, blob): (String, Vec<u8>) = conn
            .query_row(
                &format!(
                    "SELECT cycle_id, {}_blob FROM {table}",
                    artifact_blob_prefix(table)
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(cycle_id, "cycle-1");
        assert_eq!(blob, expected_blob);
    }
    let mut foreign_key_check = conn.prepare("PRAGMA foreign_key_check").unwrap();
    assert!(!foreign_key_check.exists([]).unwrap());
}
