pub(super) const MIGRATION_V47: &str = r#"
CREATE TABLE text_only_taskrun_lineage (
 taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id)=16),
 conversation_id BLOB NOT NULL CHECK(length(conversation_id)=16),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 origin_command_id BLOB NOT NULL UNIQUE CHECK(length(origin_command_id)=16),
 origin_operation INTEGER NOT NULL CHECK(origin_operation=18),
 context_scope TEXT NOT NULL CHECK(context_scope='text_only')
);
CREATE TRIGGER text_only_taskrun_lineage_immutable BEFORE UPDATE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END;
CREATE TRIGGER text_only_taskrun_lineage_no_delete BEFORE DELETE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END;
CREATE TRIGGER text_only_taskrun_lineage_no_workspace_collision BEFORE INSERT ON text_only_taskrun_lineage
WHEN EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=NEW.taskrun_id)
BEGIN SELECT RAISE(ABORT,'TaskRun lineage owner collision'); END;
"#;

const V47_TRIGGER_SQL: &[(&str, &str)] = &[
    (
        "text_only_taskrun_lineage_immutable",
        "CREATE TRIGGER text_only_taskrun_lineage_immutable BEFORE UPDATE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END",
    ),
    (
        "text_only_taskrun_lineage_no_delete",
        "CREATE TRIGGER text_only_taskrun_lineage_no_delete BEFORE DELETE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END",
    ),
    (
        "text_only_taskrun_lineage_no_workspace_collision",
        "CREATE TRIGGER text_only_taskrun_lineage_no_workspace_collision BEFORE INSERT ON text_only_taskrun_lineage WHEN EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=NEW.taskrun_id) BEGIN SELECT RAISE(ABORT,'TaskRun lineage owner collision'); END",
    ),
];

pub(super) fn apply_v47_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V47)?;
    for operation in ["insert", "update", "delete"] {
        tx.execute_batch(&v12_fence_trigger("text_only_taskrun_lineage", operation).1)?;
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(47)", [])?;
    tx.commit()
}

pub(super) fn v47_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if !matches!(version, 47..=69) {
        return Ok(false);
    }
    if !v46_matches(connection, version)? {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(
        marker,
        (47, 1, 46, 1109)
            | (47, 1, 47, 1128)
            | (48, 1, 47, 1157)
            | (48, 1, 48, 1176)
            | (49, 1, 48, 1206)
            | (49, 1, 49, 1225)
            | (50, 1, 49, 1256)
            | (50, 1, 50, 1275)
            | (51, 1, 50, 1307)
            | (51, 1, 51, 1326)
            | (52, 1, 51, 1359)
            | (52, 1, 52, 1378)
            | (53, 1, 52, 1412)
            | (53, 1, 53, 1431)
            | (54, 1, 53, 1466)
            | (54, 1, 54, 1485)
            | (55, 1, 54, 1521)
            | (55, 1, 55, 1540)
            | (56, 1, 55, 1577)
            | (56, 1, 56, 1596)
            | (57, 1, 56, 1634)
            | (57, 1, 57, 1653)
            | (58, 1, 57, 1692)
            | (58, 1, 58, 1711)
            | (59, 1, 58, 1751)
            | (59, 1, 59, 1770)
            | (60, 1, 59, 1811)
            | (60, 1, 60, 1830)
            | (61, 1, 60, 1872)
            | (61, 1, 61, 1891)
            | (62, 1, 61, 1934)
            | (62, 1, 62, 1953)
            | (63, 1, 62, 1997)
            | (63, 1, 63, 2016)
            | (64, 1, 63, 2061)
            | (64, 1, 64, 2080)
            | (65, 1, 64, 2126)
            | (65, 1, 65, 2145)
            | (66, 1, 65, 2192)
            | (66, 1, 66, 2211)
            | (67, 1, 66, 2259)
            | (67, 1, 67, 2278)
            | (68, 1, 67, 2327)
            | (68, 1, 68, 2346)
            | (69, 1, 68, 2396)
            | (69, 1, 69, 2415)
    ) {
        return Ok(false);
    }
    let expected = MIGRATION_V47
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE TABLE text_only_taskrun_lineage "))
        .expect("V47 lineage DDL is frozen");
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='text_only_taskrun_lineage'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.is_none_or(|sql| normalize_ddl(&sql) != normalize_ddl(expected)) {
        return Ok(false);
    }
    if !v47_triggers_match(connection)? {
        return Ok(false);
    }
    if !v47_rows_match(connection)? {
        return Ok(false);
    }
    Ok(true)
}

fn v47_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for (name, expected) in V47_TRIGGER_SQL {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    for operation in ["insert", "update", "delete"] {
        let (name, expected) = v12_fence_trigger("text_only_taskrun_lineage", operation);
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(&expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v47_rows_match(connection: &Connection) -> SqliteResult<bool> {
    let duplicate: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM text_only_taskrun_lineage text_lineage
          LEFT JOIN task_run_workspace_lineage workspace_lineage USING(taskrun_id)
          WHERE workspace_lineage.taskrun_id IS NOT NULL)",
        [],
        |row| row.get(0),
    )?;
    if duplicate {
        return Ok(false);
    }
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM text_only_taskrun_lineage text_lineage
          LEFT JOIN aggregate_streams stream ON stream.aggregate_type=1
            AND stream.aggregate_id=text_lineage.taskrun_id
          WHERE stream.aggregate_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    Ok(!orphan
        && crate::project_workspace::lineage::validate_all_text_only_taskrun_lineage(connection)
            .is_ok())
}
