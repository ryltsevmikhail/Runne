use gocode_store::schema::apply_migrations;
use rusqlite::Connection;

fn current() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    connection
}

#[test]
fn v17_preflight_rejects_missing_and_extra_snapshot_catalog_objects() {
    for mutation in [
        "DROP INDEX idx_aggregate_state_snapshots_head_position",
        "DROP TRIGGER aggregate_state_snapshots_bind_insert",
        "DROP TRIGGER aggregate_state_snapshots_bind_update",
        "CREATE INDEX unexpected_snapshot_index ON aggregate_state_snapshots(codec_version)",
        "CREATE TABLE unexpected_snapshot_table (value INTEGER NOT NULL)",
    ] {
        let connection = current();
        connection.execute_batch(mutation).unwrap();
        assert!(
            apply_migrations(&connection).is_err(),
            "must reject {mutation}"
        );
    }
}

#[test]
fn v17_preflight_rejects_altered_snapshot_table_sql() {
    let connection = current();
    let cookie: i64 = connection
        .pragma_query_value(None, "schema_version", |row| row.get(0))
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = ON")
        .unwrap();
    connection
        .execute(
            "UPDATE sqlite_master SET sql = replace(sql, 'codec_version INTEGER NOT NULL',
             'codec_version INTEGER') WHERE type = 'table' AND name = 'aggregate_state_snapshots'",
            [],
        )
        .unwrap();
    connection
        .execute_batch("PRAGMA writable_schema = OFF")
        .unwrap();
    connection
        .execute_batch(&format!("PRAGMA schema_version = {};", cookie + 1))
        .unwrap();
    assert!(apply_migrations(&connection).is_err());
}
