pub(super) const MIGRATION_V69: &str = include_str!("v69_permission_retained_context.sql");
include!("v69_permission_retained_context_objects.rs");

pub(super) fn apply_v69_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    if !v68_matches(&tx, 68)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.execute_batch(MIGRATION_V69)?;
    tx.execute("INSERT INTO schema_version(version) VALUES(69)", [])?;
    if !v69_matches(&tx, 69)? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.commit()
}

pub(super) fn v69_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 69
        || !v69_marker_matches(connection)?
        || !v64_matches(connection, version)?
        || !v67_structure_matches(connection)?
        || !table_sql_matches_migration(
            connection,
            "taskrun_local_permission_routes",
            MIGRATION_V68,
        )?
        || !table_sql_matches_migration(connection, "x2_permission_bindings", V69_BINDING_DDL)?
        || !v68_routes_match(connection)?
        || !v68_sidecar_rows_match(connection)?
        || !v68_foreign_keys_match(connection)?
        || !v69_binding_triggers_match(connection)?
        || !v69_context_rows_match(connection)?
    {
        return Ok(false);
    }
    for table in V68_SIDECAR_TABLES.iter().skip(1) {
        if !table_sql_matches_migration(connection, table, MIGRATION_V68)? {
            return Ok(false);
        }
    }
    for (name, sql) in V68_ROUTE_TRIGGERS
        .iter()
        .chain(V68_ROUTE_FENCE_TRIGGERS)
        .chain(V68_SIDECAR_TRIGGERS)
        .chain(V68_SIDECAR_FENCE_TRIGGERS)
    {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v69_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    v68_add_schema_extensions(tables, indexes, triggers);
    triggers.push(V69_PAIR_TRIGGER);
}

fn v69_marker_matches(connection: &Connection) -> SqliteResult<bool> {
    if !table_sql_matches_migration(
        connection,
        "schema_version",
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));",
    )? {
        return Ok(false);
    }
    let mut statement =
        connection.prepare("SELECT version FROM schema_version ORDER BY version")?;
    let actual = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let full: Vec<i64> = (1..=69).collect();
    let missing19: Vec<i64> = (1..=69).filter(|version| *version != 19).collect();
    Ok(actual == full || actual == missing19)
}
