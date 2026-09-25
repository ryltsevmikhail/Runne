pub(super) const MIGRATION_V42: &str = r#"
CREATE TABLE taskrun_fence_counters (
    taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id) = 16 AND taskrun_id != zeroblob(16)),
    last_fence INTEGER NOT NULL CHECK(last_fence > 0)
);
CREATE TABLE taskrun_assignments (
    taskrun_id BLOB NOT NULL CHECK(length(taskrun_id) = 16 AND taskrun_id != zeroblob(16)),
    attempt_id BLOB NOT NULL UNIQUE CHECK(length(attempt_id) = 16 AND attempt_id != zeroblob(16)),
    node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)),
    node_epoch INTEGER NOT NULL CHECK(node_epoch > 0),
    fence INTEGER NOT NULL CHECK(fence > 0),
    capability_descriptor TEXT NOT NULL CHECK(capability_descriptor = 'linux-executor-v1'),
    lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms > 0),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    admitted_event_id BLOB NOT NULL UNIQUE CHECK(length(admitted_event_id) = 16),
    started_event_id BLOB NOT NULL UNIQUE CHECK(length(started_event_id) = 16),
    PRIMARY KEY(taskrun_id, fence)
);
CREATE INDEX taskrun_assignments_live_node ON taskrun_assignments(node_id, node_epoch);
CREATE TRIGGER taskrun_assignments_immutable BEFORE UPDATE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END;
CREATE TRIGGER taskrun_assignments_no_delete BEFORE DELETE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END;
CREATE TABLE taskrun_claim_receipts (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    idempotency_scope_bytes BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32),
    taskrun_id BLOB NOT NULL CHECK(length(taskrun_id) = 16),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    node_id BLOB NOT NULL CHECK(length(node_id) = 16),
    node_epoch INTEGER NOT NULL CHECK(node_epoch > 0),
    fence INTEGER NOT NULL CHECK(fence > 0),
    lease_expires_at_ms INTEGER NOT NULL CHECK(lease_expires_at_ms > 0),
    new_version INTEGER NOT NULL CHECK(new_version > 0),
    admitted_event_id BLOB NOT NULL CHECK(length(admitted_event_id) = 16),
    started_event_id BLOB NOT NULL CHECK(length(started_event_id) = 16),
    UNIQUE(idempotency_scope_bytes, idempotency_key)
);
CREATE TRIGGER taskrun_claim_receipts_immutable BEFORE UPDATE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END;
CREATE TRIGGER taskrun_claim_receipts_no_delete BEFORE DELETE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END;
CREATE TRIGGER global_command_id_from_taskrun_claim_receipts
BEFORE INSERT ON taskrun_claim_receipts
WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id)
  OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_command_receipts_v42
BEFORE INSERT ON command_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
CREATE TRIGGER global_command_id_from_project_workspace_receipts_v42
BEFORE INSERT ON project_workspace_command_receipts
WHEN EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
"#;

pub(super) fn apply_v42_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V42)?;
    for table in ["taskrun_fence_counters", "taskrun_assignments", "taskrun_claim_receipts"] {
        for operation in ["insert", "update", "delete"] {
            transaction.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    transaction.execute("INSERT INTO schema_version (version) VALUES (42)", [])?;
    transaction.commit()
}

pub(super) fn v42_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 42 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(marker, (42, 1, 41, 884) | (42, 1, 42, 903)) {
        return Ok(false);
    }
    let tables = [
        V33_TABLE, V35_TABLE, TABLE, "conversation_context_scope", "execution_nodes",
        "taskrun_fence_counters", "taskrun_assignments", "taskrun_claim_receipts",
    ];
    let indexes = [V33_INDEX, "taskrun_assignments_live_node"];
    let extensions = CredentialSchemaExtensions { tables: &tables, indexes: &indexes, triggers: &[], replacements: &[] };
    Ok(catalog_marker_matches(connection)?
        && inherited_credential_guards_match(connection)?
        && v37_structure_matches(connection)?
        && v29_catalog_matches_with_extensions(connection, v32_operation_index_names(), &extensions)?
        && project_workspace_schema::v36_receipt_table_matches(connection)?
        && project_workspace_schema::validation::global_command_triggers_match(connection)?
        && v39_lineage_table_matches(connection)?
        && v40_scope_table_matches(connection)?
        && execution_node_table_matches(connection)?
        && claim_tables_match(connection)?
        && claim_immutability_triggers_match(connection)?
        && claim_global_command_triggers_match(connection)?
        && claim_fence_triggers_match(connection)?)
}

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
        let actual: Option<String> = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        ).optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(expected)) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn claim_immutability_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for (name, expected) in [
        ("taskrun_assignments_immutable", "CREATE TRIGGER taskrun_assignments_immutable BEFORE UPDATE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END"),
        ("taskrun_assignments_no_delete", "CREATE TRIGGER taskrun_assignments_no_delete BEFORE DELETE ON taskrun_assignments BEGIN SELECT RAISE(ABORT, 'TaskRun assignment is immutable'); END"),
        ("taskrun_claim_receipts_immutable", "CREATE TRIGGER taskrun_claim_receipts_immutable BEFORE UPDATE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END"),
        ("taskrun_claim_receipts_no_delete", "CREATE TRIGGER taskrun_claim_receipts_no_delete BEFORE DELETE ON taskrun_claim_receipts BEGIN SELECT RAISE(ABORT, 'TaskRun claim receipt is immutable'); END"),
    ] {
        let actual: Option<String> = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1", [name], |row| row.get(0),
        ).optional()?;
        if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(expected)) { return Ok(false); }
    }
    Ok(true)
}

fn claim_fence_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    for table in ["taskrun_fence_counters", "taskrun_assignments", "taskrun_claim_receipts"] {
        for operation in ["insert", "update", "delete"] {
            let (name, expected) = v12_fence_trigger(table, operation);
            let actual: Option<String> = connection.query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [&name], |row| row.get(0),
            ).optional()?;
            if actual.is_none_or(|actual| normalize_sql(&actual) != normalize_sql(&expected)) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn claim_tables_match(connection: &Connection) -> SqliteResult<bool> {
    for table in ["taskrun_fence_counters", "taskrun_assignments", "taskrun_claim_receipts"] {
        let actual: Option<String> = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", [table], |row| row.get(0),
        ).optional()?;
        let expected = MIGRATION_V42.split(';').map(str::trim)
            .find(|statement| statement.starts_with(&format!("CREATE TABLE {table} ")));
        if actual.is_none_or(|actual| expected.is_none_or(|expected| normalize_ddl(&actual) != normalize_ddl(expected))) {
            return Ok(false);
        }
    }
    Ok(true)
}
