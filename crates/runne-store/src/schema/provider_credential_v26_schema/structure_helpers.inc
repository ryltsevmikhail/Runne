// Structure helpers for the V26 predecessor chain (split from the
// predecessor matcher to keep each module under the size budget).

fn inherited_indexes_match(connection: &Connection) -> SqliteResult<bool> {
    inherited_indexes_match_with_operation_indexes(connection, false)
}

fn inherited_indexes_match_with_v32_operation_indexes(
    connection: &Connection,
) -> SqliteResult<bool> {
    inherited_indexes_match_with_operation_indexes(connection, true)
}

fn inherited_indexes_match_with_operation_indexes(
    connection: &Connection,
    uses_v32_operation_indexes: bool,
) -> SqliteResult<bool> {
    Ok(index_sql_matches_v16(connection)?
        && v17_index_matches(connection)?
        && index_matches(
            connection,
            "idx_aggregate_state_snapshots_head_position",
            "aggregate_state_snapshots",
            &["head_global_position"],
        )?
        && index_matches(
            connection,
            "idx_process_registry_owner",
            "process_registry",
            &["principal_id", "process_id"],
        )?
        && index_matches(
            connection,
            "idx_approvals_pending",
            "approvals",
            &["principal_id", "state", "expires_at", "approval_id"],
        )?
        && if uses_v32_operation_indexes {
            v32_operation_indexes_match(connection)?
        } else {
            v24_index_matches(connection, "provider_credential_one_non_terminal_operation")?
        })
}

fn v18_global_trigger_matches(connection: &Connection) -> SqliteResult<bool> {
    [
        (
            "global_command_id_from_command_receipts",
            "CREATE TRIGGER global_command_id_from_command_receipts BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
        (
            "global_command_id_from_project_workspace_receipts",
            "CREATE TRIGGER global_command_id_from_project_workspace_receipts BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
    ]
    .into_iter()
    .try_fold(true, |matches, (name, source)| {
        Ok(matches && v24_trigger_matches(connection, name, source)?)
    })
}

fn v22_process_registry_matches(connection: &Connection) -> SqliteResult<bool> {
    let v21 = MIGRATION_V21
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE process_registry "))
        .expect("V21 process registry is frozen");
    let column = MIGRATION_V22
        .split("ADD COLUMN")
        .nth(1)
        .expect("V22 process intent column is frozen")
        .trim()
        .trim_end_matches(';');
    let expected = v21.replacen(
        ",\n    UNIQUE(",
        &format!(",\n    {column},\n    UNIQUE("),
        1,
    );
    table_sql_matches(connection, "process_registry", &expected)
}

fn v26_marker_matches(connection: &Connection) -> SqliteResult<bool> {
    let tuple: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(tuple, (26, 1, 25, 332) | (26, 1, 26, 351)))
}

fn v26_table_source(name: &str) -> String {
    let table = MIGRATION_V26
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE TABLE {name}")))
        .expect("V26 table is frozen");
    normalize_v24_ddl(table)
}

fn v26_trigger_source(name: &str) -> &'static str {
    let start = MIGRATION_V26
        .find(&format!("CREATE TRIGGER {name}"))
        .expect("V26 trigger is frozen");
    let end = MIGRATION_V26[start..]
        .find("END;")
        .expect("V26 trigger end")
        + start
        + 3;
    &MIGRATION_V26[start..end]
}
