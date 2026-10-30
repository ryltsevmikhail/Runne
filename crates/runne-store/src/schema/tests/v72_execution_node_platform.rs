use std::fs;
use std::path::{Path, PathBuf};

fn legacy_v71_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schema/v71-legacy-execution-node.sqlite")
}

fn copy_fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("event-log.db");
    fs::copy(legacy_v71_fixture(), &path).unwrap();
    (directory, path)
}

struct Shape {
    table_sql: String,
    rows: Vec<String>,
    versions: Vec<i64>,
    triggers: Vec<String>,
}

fn shape(connection: &Connection) -> Shape {
    let table_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_nodes'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let rows = connection
        .prepare(
            "SELECT hex(node_id)||'|'||launch_generation||'|'||descriptor_version||'|'||
                    platform||'|'||executor_protocol||'|'||workspace_backend||'|'||
                    capacity||'|'||heartbeat_at_ms||'|'||expires_at_ms
             FROM execution_nodes ORDER BY node_id",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<SqliteResult<Vec<_>>>()
        .unwrap();
    let versions = connection
        .prepare("SELECT version FROM schema_version ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<SqliteResult<Vec<_>>>()
        .unwrap();
    let mut triggers = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='execution_nodes' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<SqliteResult<Vec<_>>>()
        .unwrap();
    triggers.sort();
    Shape {
        table_sql,
        rows,
        versions,
        triggers,
    }
}

fn foreign_key_violations(connection: &Connection) -> i64 {
    connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// The historical fixture carries the real v71 shape: schema_version 1..71,
/// the old `platform = 'linux'` check and the three live fence triggers.
#[test]
fn legacy_v71_fixture_opens_and_is_repaired_in_place() {
    let (_directory, path) = copy_fixture();
    let before = {
        let raw = Connection::open(&path).unwrap();
        let before = shape(&raw);
        assert!(before.table_sql.contains("platform = 'linux'"));
        assert_eq!(before.rows.len(), 2);
        assert_eq!(before.versions, (1..=71).collect::<Vec<_>>());
        assert_eq!(before.triggers.len(), 3);
        before
    };

    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let repaired = shape(&connection);
    assert!(
        repaired
            .table_sql
            .contains("platform IN ('linux','darwin')")
    );
    assert_eq!(repaired.rows, before.rows);
    assert_eq!(repaired.versions, before.versions);
    assert_eq!(repaired.triggers.len(), 3);
    assert_eq!(foreign_key_violations(&connection), 0);
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    drop(connection);

    // A second open runs the repair again and must be a no-op.
    let reopened = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&reopened).unwrap();
    let again = shape(&reopened);
    assert_eq!(again.table_sql, repaired.table_sql);
    assert_eq!(again.rows, before.rows);
    assert_eq!(again.versions, before.versions);
    assert_eq!(again.triggers, repaired.triggers);
}

#[test]
fn failed_postcondition_rolls_back_and_keeps_database_openable() {
    let (_directory, path) = copy_fixture();
    {
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch("DROP TRIGGER schema_v12_fence_execution_nodes_update")
            .unwrap();
    }
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    let before = shape(&connection);
    let error = apply_migrations(&connection).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("execution_nodes platform repair postcondition failed"));
    assert!(message.contains("fence triggers changed"));
    assert!(!message.contains("Query is not read-only"));
    let after = shape(&connection);
    assert!(after.table_sql.contains("platform = 'linux'"));
    assert_eq!(after.rows, before.rows);
    assert_eq!(after.versions, before.versions);
    drop(connection);

    // The rolled-back database must still pass admission on the next open.
    let reopened = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    let reopened_shape = shape(&reopened);
    assert!(reopened_shape.table_sql.contains("platform = 'linux'"));
    assert_eq!(reopened_shape.rows, before.rows);
    assert_eq!(reopened_shape.versions, before.versions);
}
