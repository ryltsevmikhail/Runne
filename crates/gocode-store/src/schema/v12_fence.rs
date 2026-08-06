fn v12_write_latch_closed(conn: &Connection) -> SqliteResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_upgrade_write_latch WHERE id = 1)",
        [],
        |row| row.get(0),
    )
}

fn authoritative_v12_tables(conn: &Connection) -> SqliteResult<Vec<String>> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('schema_version', 'schema_upgrade_fence', 'schema_upgrade_write_latch', 'provider_effect_starts') ORDER BY name")?.query_map([], |row| row.get::<_, String>(0))?.collect()
}

fn v12_fence_trigger(table: &str, operation: &str) -> (String, String) {
    let operation = match operation {
        "insert" => "INSERT",
        "update" => "UPDATE",
        "delete" => "DELETE",
        _ => unreachable!(),
    };
    let name = format!(
        "schema_v12_fence_{table}_{}",
        operation.to_ascii_lowercase()
    );
    (
        name.clone(),
        format!(
            "CREATE TRIGGER \"{name}\" AFTER {operation} ON \"{table}\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        ),
    )
}

fn v12_guard_triggers() -> [(&'static str, &'static str, &'static str); 5] {
    [
        (
            "schema_v12_guard_fence_insert",
            "schema_upgrade_fence",
            "CREATE TRIGGER \"schema_v12_guard_fence_insert\" BEFORE INSERT ON \"schema_upgrade_fence\" BEGIN SELECT RAISE(ABORT, 'schema upgrade fence is immutable'); END",
        ),
        (
            "schema_v12_guard_fence_update",
            "schema_upgrade_fence",
            "CREATE TRIGGER \"schema_v12_guard_fence_update\" BEFORE UPDATE ON \"schema_upgrade_fence\" BEGIN SELECT RAISE(ABORT, 'schema upgrade fence is immutable'); END",
        ),
        (
            "schema_v12_guard_fence_delete",
            "schema_upgrade_fence",
            "CREATE TRIGGER \"schema_v12_guard_fence_delete\" BEFORE DELETE ON \"schema_upgrade_fence\" BEGIN SELECT RAISE(ABORT, 'schema upgrade fence is immutable'); END",
        ),
        (
            "schema_v12_guard_latch_update",
            "schema_upgrade_write_latch",
            "CREATE TRIGGER \"schema_v12_guard_latch_update\" BEFORE UPDATE ON \"schema_upgrade_write_latch\" BEGIN SELECT RAISE(ABORT, 'schema upgrade latch is irreversible'); END",
        ),
        (
            "schema_v12_guard_latch_delete",
            "schema_upgrade_write_latch",
            "CREATE TRIGGER \"schema_v12_guard_latch_delete\" BEFORE DELETE ON \"schema_upgrade_write_latch\" BEGIN SELECT RAISE(ABORT, 'schema upgrade latch is irreversible'); END",
        ),
    ]
}

fn install_v12_fence_triggers(conn: &Connection) -> SqliteResult<()> {
    for table in authoritative_v12_tables(conn)? {
        for operation in ["insert", "update", "delete"] {
            conn.execute_batch(&v12_fence_trigger(&table, operation).1)?;
        }
    }
    for (_, _, sql) in v12_guard_triggers() {
        conn.execute_batch(sql)?;
    }
    Ok(())
}

fn install_missing_v12_fence_triggers(conn: &Connection) -> SqliteResult<()> {
    for table in authoritative_v12_tables(conn)? {
        for operation in ["insert", "update", "delete"] {
            let (name, sql) = v12_fence_trigger(&table, operation);
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
                [&name],
                |row| row.get(0),
            )?;
            if !exists {
                conn.execute_batch(&sql)?;
            }
        }
    }
    Ok(())
}

fn v12_fence_triggers_match(conn: &Connection) -> SqliteResult<bool> {
    let tables = authoritative_v12_tables(conn)?;
    let expected = tables.len() * 3 + v12_guard_triggers().len();
    let actual: usize = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'",
        [],
        |row| row.get(0),
    )?;
    if actual != expected {
        return Ok(false);
    }
    for table in tables {
        for operation in ["insert", "update", "delete"] {
            let (name, sql) = v12_fence_trigger(&table, operation);
            let actual: Option<String> = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(&sql)) {
                return Ok(false);
            }
        }
    }
    for (name, _, sql) in v12_guard_triggers() {
        let actual: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(sql)) {
            return Ok(false);
        }
    }
    Ok(true)
}
