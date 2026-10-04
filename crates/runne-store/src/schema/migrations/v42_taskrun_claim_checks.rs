fn claim_global_command_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for (name, expected) in [
        (
            "global_command_id_from_taskrun_claim_receipts",
            "CREATE TRIGGER global_command_id_from_taskrun_claim_receipts BEFORE INSERT ON taskrun_claim_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
        (
            "global_command_id_from_command_receipts_v42",
            "CREATE TRIGGER global_command_id_from_command_receipts_v42 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
        (
            "global_command_id_from_project_workspace_receipts_v42",
            "CREATE TRIGGER global_command_id_from_project_workspace_receipts_v42 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id = NEW.command_id) BEGIN SELECT RAISE(ABORT, 'global command id collision'); END",
        ),
    ] {
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
    Ok(true)
}

fn claim_immutability_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for (name, expected) in [
        (
            "taskrun_assignments_immutable",
            "CREATE TRIGGER taskrun_assignments_immutable BEFORE UPDATE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END",
        ),
        (
            "taskrun_assignments_no_delete",
            "CREATE TRIGGER taskrun_assignments_no_delete BEFORE DELETE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END",
        ),
        (
            "taskrun_claim_receipts_immutable",
            "CREATE TRIGGER taskrun_claim_receipts_immutable BEFORE UPDATE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END",
        ),
        (
            "taskrun_claim_receipts_no_delete",
            "CREATE TRIGGER taskrun_claim_receipts_no_delete BEFORE DELETE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END",
        ),
    ] {
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
    Ok(true)
}

fn claim_fence_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for table in [
        "taskrun_fence_counters",
        "taskrun_assignments",
        "taskrun_claim_receipts",
    ] {
        for operation in ["insert", "update", "delete"] {
            let (name, expected) = v12_fence_trigger(table, operation);
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
    }
    Ok(true)
}

fn claim_tables_match(connection: &Connection) -> SqliteResult<bool> {
    for table in [
        "taskrun_fence_counters",
        "taskrun_assignments",
        "taskrun_claim_receipts",
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()?;
        let expected = MIGRATION_V42
            .split(';')
            .map(str::trim)
            .find(|statement| statement.starts_with(&format!("CREATE TABLE {table} ")));
        if actual.is_none_or(|actual| {
            expected.is_none_or(|expected| normalize_ddl(&actual) != normalize_ddl(expected))
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}
