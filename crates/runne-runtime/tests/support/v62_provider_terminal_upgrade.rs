use rusqlite::Connection;

/// Downgrades only the v63 receipt schema on a test database that was built
/// through the lawful current provider pipeline. All earlier rows are kept.
pub fn remove_v63_for_v62_upgrade(connection: &Connection, omit_v19_marker: bool) {
    let triggers = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='trigger'
             AND (name LIKE 'provider_unknown_terminal_receipts%'
               OR name LIKE 'schema_v12_fence_provider_unknown_terminal_receipts_%')
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for trigger in triggers {
        connection
            .execute_batch(&format!("DROP TRIGGER \"{trigger}\""))
            .unwrap();
    }
    connection
        .execute_batch(
            "DROP TABLE provider_unknown_terminal_receipts;
             DELETE FROM schema_version WHERE version=63;",
        )
        .unwrap();
    if omit_v19_marker {
        connection
            .execute("DELETE FROM schema_version WHERE version=19", [])
            .unwrap();
    }
}
