// ── Migration V37: taskrun lineage admits the submit origin (20) ──────────
//
// X2 submit commits TaskRunCreated+TaskRunQueued under its own
// `SubmitTaskRun` operation; its workspace lineage row must carry
// origin_operation = 20 instead of masquerading as a CreateTaskRun origin.
// SQLite CHECK constraints are immutable, so the lineage table is rebuilt.

pub(super) const MIGRATION_V37_LINEAGE: &str = r#"
CREATE TABLE task_run_workspace_lineage_v37 (
    taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id) = 16),
    workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16),
    project_id BLOB CHECK(project_id IS NULL OR length(project_id) = 16),
    classification TEXT NOT NULL CHECK(classification IN ('canonical', 'legacy_unbound')),
    origin_command_id BLOB NOT NULL UNIQUE CHECK(length(origin_command_id) = 16),
    origin_operation INTEGER NOT NULL CHECK(origin_operation IN (1, 18, 20)),
    CHECK((classification = 'canonical' AND project_id IS NOT NULL) OR
          (classification = 'legacy_unbound' AND project_id IS NULL))
);
"#;

pub(super) fn apply_v37_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V37_LINEAGE)?;
    transaction.execute_batch(
        "INSERT INTO task_run_workspace_lineage_v37
         SELECT * FROM task_run_workspace_lineage;
         DROP TABLE task_run_workspace_lineage;
         ALTER TABLE task_run_workspace_lineage_v37
         RENAME TO task_run_workspace_lineage;",
    )?;
    // Dropping the old table removed its V12 fence triggers; reinstall them
    // for the rebuilt table exactly like the V36 receipt rebuild does.
    for operation in ["insert", "update", "delete"] {
        transaction.execute_batch(&v12_fence_trigger("task_run_workspace_lineage", operation).1)?;
    }
    transaction.execute("INSERT INTO schema_version (version) VALUES (37)", [])?;
    transaction.commit()
}

pub(super) fn v37_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 37 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let inherited = v35_structure_matches_with_v36_receipt(connection, true, true)?;
    let receipts = project_workspace_schema::v36_receipt_table_matches(connection)?;
    let triggers = project_workspace_schema::global_command_triggers_match(connection)?;
    Ok(
        matches!(marker, (37, 1, 36, 684) | (37, 1, 37, 703)) && inherited && receipts && triggers
            && v37_lineage_table_matches(connection)?,
    )
}

pub(super) fn v37_lineage_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            ["task_run_workspace_lineage"],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V37_LINEAGE
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE task_run_workspace_lineage_v37 "))
        .map(|statement| {
            statement.replace(
                "CREATE TABLE task_run_workspace_lineage_v37",
                "CREATE TABLE \"task_run_workspace_lineage\"",
            )
        });
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| {
            normalize_ddl(&actual) == normalize_ddl(&expected)
        })
    }))
}
