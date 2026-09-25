pub(super) const MIGRATION_V41: &str = r#"
CREATE TABLE execution_nodes (
    node_id BLOB PRIMARY KEY CHECK(length(node_id) = 16 AND node_id != zeroblob(16)),
    launch_generation INTEGER NOT NULL CHECK(launch_generation > 0),
    descriptor_version INTEGER NOT NULL CHECK(descriptor_version = 1),
    platform TEXT NOT NULL CHECK(platform = 'linux'),
    executor_protocol TEXT NOT NULL CHECK(executor_protocol = 'runne-taskrun-v1'),
    workspace_backend TEXT NOT NULL CHECK(workspace_backend = 'git-worktree-v1'),
    capacity INTEGER NOT NULL CHECK(capacity > 0 AND capacity <= 4294967295),
    heartbeat_at_ms INTEGER NOT NULL CHECK(heartbeat_at_ms > 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > heartbeat_at_ms)
);
"#;

pub(super) fn apply_v41_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V41)?;
    for operation in ["insert", "update", "delete"] {
        transaction.execute_batch(&v12_fence_trigger("execution_nodes", operation).1)?;
    }
    transaction.execute("INSERT INTO schema_version (version) VALUES (41)", [])?;
    transaction.commit()
}

pub(super) fn v41_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 41 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(marker, (41, 1, 40, 842) | (41, 1, 41, 861)) {
        return Ok(false);
    }
    Ok(catalog_marker_matches(connection)?
        && inherited_credential_guards_match(connection)?
        && v37_structure_matches(connection)?
        && v41_catalog_matches(connection)?
        && project_workspace_schema::v36_receipt_table_matches(connection)?
        && project_workspace_schema::validation::global_command_triggers_match(connection)?
        && v39_lineage_table_matches(connection)?
        && v40_scope_table_matches(connection)?
        && execution_node_fence_triggers_match(connection)?)
}

fn execution_node_fence_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("execution_nodes", operation);
        let actual: Option<String> = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [&name],
            |row| row.get(0),
        ).optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(&expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v41_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    Ok(v29_catalog_matches_with_extensions(
        connection,
        v35_operation_index_names(),
        &CredentialSchemaExtensions {
            tables: &[V33_TABLE, V35_TABLE, TABLE, "conversation_context_scope", "execution_nodes"],
            indexes: &[V33_INDEX],
            triggers: &[],
            replacements: &[],
        },
    )? && execution_node_table_matches(connection)?)
}

fn execution_node_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_nodes'",
        [], |row| row.get(0),
    ).optional()?;
    let expected = MIGRATION_V41
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE execution_nodes "));
    Ok(actual.is_some_and(|actual| expected.is_some_and(|expected| normalize_ddl(&actual) == normalize_ddl(expected))))
}
