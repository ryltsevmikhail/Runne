//! Released V8 to strict provider-schema upgrade regressions.

use gocode_store::schema::{CURRENT_SCHEMA_VERSION, apply_migrations};
use rusqlite::{Connection, params};

fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
    .unwrap()
}

fn released_v8_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    apply_migrations(&conn).unwrap();
    let triggers = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'schema_v12_%'",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in triggers {
        conn.execute_batch(&format!("DROP TRIGGER \"{trigger}\";"))
            .unwrap();
    }
    conn.execute_batch(
        "DROP TRIGGER global_command_id_from_command_receipts;
         DROP TABLE task_run_workspace_lineage;
         DROP TABLE root_admission_nonces;
         DROP TABLE project_workspace_command_receipts;
         DROP TABLE workspaces;
         DROP TABLE projects;
         DROP TABLE schema_upgrade_write_latch;
         DROP TABLE schema_upgrade_fence;
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
         DROP TABLE provider_effect_authorities;
         DROP TABLE provider_dispatch_attempts;
         DROP TABLE provider_prepared_requests;
         DROP TABLE schema_lineage;
         DROP TABLE consumption_intents;
         DROP TABLE verification_evidence;
         DELETE FROM schema_version WHERE version >= 9;",
    )
    .unwrap();
    conn
}

fn schema_objects(conn: &Connection) -> Vec<(String, String)> {
    conn.prepare("SELECT type, name FROM sqlite_master ORDER BY type, name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn released_v8_upgrades_to_current_schema_and_rejects_invalid_values() {
    let conn = released_v8_db();
    apply_migrations(&conn).unwrap();
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    assert_eq!(CURRENT_SCHEMA_VERSION, 16);
    assert_eq!(version, 16);
    assert!(table_exists(&conn, "verification_evidence"));
    assert!(table_exists(&conn, "consumption_intents"));
    assert!(!table_exists(&conn, "verification_evidence_v10"));
    assert!(!table_exists(&conn, "consumption_intents_v11"));
    for table in [
        "schema_upgrade_fence",
        "schema_upgrade_write_latch",
        "provider_runtime_authority_state",
        "provider_execution_admissions",
        "provider_budget_reservations",
        "provider_journal_key_refs",
        "provider_terminal_outbox",
        "provider_effect_starts",
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
        "task_run_workspace_lineage",
    ] {
        assert!(table_exists(&conn, table), "missing released table {table}");
    }
    for (table, column) in [
        (
            "provider_runtime_authority_state",
            "activation_binding_kind",
        ),
        (
            "provider_runtime_authority_state",
            "activation_binding_digest",
        ),
        ("provider_execution_admissions", "activation_binding_kind"),
        ("provider_execution_admissions", "activation_binding_digest"),
    ] {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
                [table, column],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing V14 column {table}.{column}");
    }

    let digest = [0xA5_u8; 32];
    for (sql, identity) in [
        (
            "INSERT INTO consumption_intents VALUES (?1, 'key', 'Reserved', ?2, ?2, ?2)",
            &[0_u8; 15][..],
        ),
        (
            "INSERT INTO consumption_intents VALUES (?1, 'key-2', 'Unknown', ?2, ?2, ?2)",
            &[0_u8; 16][..],
        ),
    ] {
        assert!(
            conn.execute(sql, params![identity, digest.as_slice()])
                .is_err()
        );
    }
    for sql in [
        "INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 0, 0, ?2, '', 'store', 'producer', 0, 'sqlite')",
        "INSERT INTO verification_evidence VALUES (?1, ?1, ?1, ?2, 6, 0, ?2, 'blob:test', 'store', 'producer', 0, 'sqlite')",
    ] {
        assert!(
            conn.execute(sql, params![[0_u8; 16].as_slice(), digest.as_slice()])
                .is_err()
        );
    }
}

#[test]
fn failed_v8_to_v9_upgrade_is_atomic() {
    let conn = released_v8_db();
    let before = schema_objects(&conn);
    conn.execute_batch(
        "CREATE TRIGGER reject_v9_marker BEFORE INSERT ON schema_version
         WHEN NEW.version = 9 BEGIN SELECT RAISE(ABORT, 'test V9 marker rejection'); END;",
    )
    .unwrap();
    assert!(apply_migrations(&conn).is_err());
    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 8);
    assert!(!table_exists(&conn, "verification_evidence"));
    assert!(!table_exists(&conn, "consumption_intents"));
    assert!(!table_exists(&conn, "schema_lineage"));
    let mut expected = before;
    expected.push(("trigger".to_owned(), "reject_v9_marker".to_owned()));
    expected.sort_unstable();
    assert_eq!(schema_objects(&conn), expected);
}

#[test]
fn candidate_only_markers_are_rejected_without_mutation() {
    for marker in [9, 10, 11] {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE TABLE candidate_only (value TEXT NOT NULL);",
        )
        .unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [marker])
            .unwrap();
        conn.execute("INSERT INTO candidate_only VALUES ('unchanged')", [])
            .unwrap();
        let before = schema_objects(&conn);
        assert!(matches!(
            apply_migrations(&conn),
            Err(rusqlite::Error::InvalidQuery)
        ));
        assert_eq!(schema_objects(&conn), before);
        assert_eq!(
            conn.query_row("SELECT value FROM candidate_only", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "unchanged"
        );
    }
}
