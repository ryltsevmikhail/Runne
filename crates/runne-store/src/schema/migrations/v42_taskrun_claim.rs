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
    v42_structure_matches(connection, false)
}

pub(super) fn v42_structure_matches(
    connection: &Connection,
    include_v43_extensions: bool,
) -> SqliteResult<bool> {
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let marker_matches = if include_v43_extensions {
        matches!(marker, (43, 1, 42, 927) | (43, 1, 43, 946) | (44, 1, 43, 971) | (44, 1, 44, 990) | (45, 1, 44, 1016) | (45, 1, 45, 1035) | (46, 1, 45, 1062) | (46, 1, 46, 1081) | (47, 1, 46, 1109) | (47, 1, 47, 1128) | (48, 1, 47, 1157) | (48, 1, 48, 1176))
    } else {
        matches!(marker, (42, 1, 41, 884) | (42, 1, 42, 903))
    };
    if !marker_matches {
        return Ok(false);
    }
    let mut tables = vec![
        V33_TABLE, V35_TABLE, TABLE, "conversation_context_scope", "execution_nodes",
        "taskrun_fence_counters", "taskrun_assignments", "taskrun_claim_receipts",
    ];
    let mut indexes = vec![V33_INDEX, "taskrun_assignments_live_node"];
    let mut triggers = Vec::new();
    if include_v43_extensions {
        tables.extend(["taskrun_assignment_occupations", "taskrun_assignment_lease_renewals"]);
        indexes.push("taskrun_assignment_occupations_capacity");
        triggers.extend([
            (
                "taskrun_assignment_lease_renewals_immutable",
                "CREATE TRIGGER taskrun_assignment_lease_renewals_immutable BEFORE UPDATE ON taskrun_assignment_lease_renewals BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END",
            ),
            (
                "taskrun_assignment_lease_renewals_no_delete",
                "CREATE TRIGGER taskrun_assignment_lease_renewals_no_delete BEFORE DELETE ON taskrun_assignment_lease_renewals BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END",
            ),
        ]);
    }
    if marker.0 >= 44 {
        tables.push("taskrun_dispatch_intents");
        triggers.extend([
            ("taskrun_dispatch_intents_immutable", "CREATE TRIGGER taskrun_dispatch_intents_immutable BEFORE UPDATE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END"),
            ("taskrun_dispatch_intents_no_delete", "CREATE TRIGGER taskrun_dispatch_intents_no_delete BEFORE DELETE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END"),
            ("taskrun_occupation_intent_guard", "CREATE TRIGGER taskrun_occupation_intent_guard BEFORE UPDATE OF dispatch_intent ON taskrun_assignment_occupations WHEN (NEW.dispatch_intent='present' AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=NEW.taskrun_id AND i.fence=NEW.fence AND i.attempt_id=NEW.attempt_id AND i.node_id=NEW.node_id AND i.node_epoch=NEW.node_epoch AND i.state='present')) OR (OLD.dispatch_intent IN ('present','unknown') AND NEW.dispatch_intent!=OLD.dispatch_intent) BEGIN SELECT RAISE(ABORT,'dispatch intent evidence mismatch'); END"),
        ]);
    }
    if marker.0 >= 45 {
        tables.push("taskrun_no_effect_release_receipts");
        triggers.extend([
            ("taskrun_no_effect_release_immutable", "CREATE TRIGGER taskrun_no_effect_release_immutable BEFORE UPDATE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END"),
            ("taskrun_no_effect_release_no_delete", "CREATE TRIGGER taskrun_no_effect_release_no_delete BEFORE DELETE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END"),
            ("global_command_id_from_release_v45", "CREATE TRIGGER global_command_id_from_release_v45 BEFORE INSERT ON taskrun_no_effect_release_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_command_receipts_v45", "CREATE TRIGGER global_command_id_from_command_receipts_v45 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_project_workspace_receipts_v45", "CREATE TRIGGER global_command_id_from_project_workspace_receipts_v45 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_taskrun_claim_receipts_v45", "CREATE TRIGGER global_command_id_from_taskrun_claim_receipts_v45 BEFORE INSERT ON taskrun_claim_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_lease_renewals_v45", "CREATE TRIGGER global_command_id_from_lease_renewals_v45 BEFORE INSERT ON taskrun_assignment_lease_renewals WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.renewal_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
        ]);
    }
    if marker.0 >= 46 {
        tables.push("taskrun_provider_bindings");
        triggers.extend([
            ("taskrun_provider_bindings_immutable", "CREATE TRIGGER taskrun_provider_bindings_immutable BEFORE UPDATE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END"),
            ("taskrun_provider_bindings_no_delete", "CREATE TRIGGER taskrun_provider_bindings_no_delete BEFORE DELETE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END"),
        ]);
    }
    if marker.0 >= 48 {
        tables.push("conversation_writer_leases");
    }
    if marker.0 >= 47 {
        tables.push("text_only_taskrun_lineage");
        triggers.extend([
            ("text_only_taskrun_lineage_immutable", "CREATE TRIGGER text_only_taskrun_lineage_immutable BEFORE UPDATE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END"),
            ("text_only_taskrun_lineage_no_delete", "CREATE TRIGGER text_only_taskrun_lineage_no_delete BEFORE DELETE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END"),
            ("text_only_taskrun_lineage_no_workspace_collision", "CREATE TRIGGER text_only_taskrun_lineage_no_workspace_collision BEFORE INSERT ON text_only_taskrun_lineage WHEN EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=NEW.taskrun_id) BEGIN SELECT RAISE(ABORT,'TaskRun lineage owner collision'); END"),
            ("schema_v12_fence_text_only_taskrun_lineage_insert", "CREATE TRIGGER \"schema_v12_fence_text_only_taskrun_lineage_insert\" AFTER INSERT ON \"text_only_taskrun_lineage\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_text_only_taskrun_lineage_update", "CREATE TRIGGER \"schema_v12_fence_text_only_taskrun_lineage_update\" AFTER UPDATE ON \"text_only_taskrun_lineage\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_text_only_taskrun_lineage_delete", "CREATE TRIGGER \"schema_v12_fence_text_only_taskrun_lineage_delete\" AFTER DELETE ON \"text_only_taskrun_lineage\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ]);
    }
    let extensions = CredentialSchemaExtensions { tables: &tables, indexes: &indexes, triggers: &triggers, replacements: &[] };
    let checks = [
        ("catalog-marker", catalog_marker_matches(connection)?),
        ("credential-guards", inherited_credential_guards_match(connection)?),
        ("v37", v37_structure_matches(connection)?),
        ("v29-catalog", v29_catalog_matches_with_extensions(connection, v35_operation_index_names(), &extensions)?),
        ("v36-receipt", project_workspace_schema::v36_receipt_table_matches(connection)?),
        ("global-workspace", project_workspace_schema::validation::global_command_triggers_match(connection)?),
        ("v39-lineage", v39_lineage_table_matches(connection)?),
        ("v40-scope", v40_scope_table_matches(connection)?),
        ("v41-node", execution_node_table_matches(connection)?),
        ("v42-claim", claim_tables_match(connection)?),
        ("v42-immutability", claim_immutability_triggers_match(connection)?),
        ("v42-global", claim_global_command_triggers_match(connection)?),
        ("v42-fence", claim_fence_triggers_match(connection)?),
    ];
    Ok(checks.iter().all(|(_, matches)| *matches))
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
