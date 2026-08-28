const V26_TABLE: &str = "provider_online_credential_effect_bindings";
const V26_ISSUANCE_EVIDENCE_TABLE: &str = "provider_online_dispatch_issuance_evidence";
const V26_CLAIM_PROVIDER_TABLE: &str = "provider_online_dispatch_claim_providers";
const V26_TRIGGERS: [&str; 9] = [
    "provider_online_dispatch_issuance_evidence_insert_current",
    "provider_online_dispatch_issuance_evidence_immutable",
    "provider_online_dispatch_issuance_evidence_no_delete",
    "provider_online_dispatch_claim_provider_insert_authorized",
    "provider_online_dispatch_claim_provider_immutable",
    "provider_online_dispatch_claim_provider_no_delete",
    "provider_online_credential_effect_binding_insert_current",
    "provider_online_credential_effect_binding_immutable",
    "provider_online_credential_effect_binding_no_delete",
];

pub(super) fn v26_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 26 || !v26_predecessor_matches(connection)? || !v26_marker_matches(connection)? {
        return Ok(false);
    }
    if !v26_catalog_matches(connection)? {
        return Ok(false);
    }
    for table in [
        V26_ISSUANCE_EVIDENCE_TABLE,
        V26_CLAIM_PROVIDER_TABLE,
        V26_TABLE,
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_none_or(|sql| normalize_v24_ddl(&sql) != v26_table_source(table)) {
            return Ok(false);
        }
    }
    V26_TRIGGERS.into_iter().try_fold(true, |valid, name| {
        let source = v26_trigger_source(name);
        Ok(valid && v24_trigger_matches(connection, name, source)?)
    })
}

pub(super) fn v26_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    let mut tables = RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "provider_credential_versions",
        "provider_credential_clock_high_water",
        "provider_credential_provisions",
        "provider_credential_effect_bindings",
        "bootstrap_reservations",
        "bootstrap_reservation_tombstones",
        "bootstrap_last_observed_clock",
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
        "workspace_identity_history",
        "task_run_workspace_lineage",
        "aggregate_state_snapshots",
        "process_registry",
        "process_output",
        "approvals",
        "provider_credential_operations",
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
        V26_ISSUANCE_EVIDENCE_TABLE,
        V26_CLAIM_PROVIDER_TABLE,
        V26_TABLE,
    ]);
    let mut indexes = RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
        "bootstrap_reservation_unexpired",
        "idx_aggregate_state_snapshots_head_position",
        "idx_process_registry_owner",
        "idx_approvals_pending",
        "provider_credential_one_non_terminal_operation",
    ]);
    released_catalog_matches_with_indexes(connection, &tables, &indexes)
}

fn v26_predecessor_matches(connection: &Connection) -> SqliteResult<bool> {
    v26_predecessor_matches_with(
        connection,
        v25_operation_table_matches,
        v26_trigger_catalog::matches,
    )
}

pub(super) fn v26_predecessor_matches_with(
    connection: &Connection,
    operation_table_matches: fn(&Connection) -> SqliteResult<bool>,
    trigger_catalog_matches: fn(&Connection) -> SqliteResult<bool>,
) -> SqliteResult<bool> {
    if !v18_global_trigger_matches(connection)? {
        return Ok(false);
    }
    if !trigger_catalog_matches(connection)? {
        return Ok(false);
    }
    let v12 = provider_v12_core_matches(connection)?;
    let v13 = v13_unchanged_tables_match(connection)?;
    let v14 = provider_schema::v14_base_matches(connection, v12, v13)?;
    if !v14
        || !provider_schema::v15_base_matches(connection, v14)?
        || !operation_table_matches(connection)?
        || !v24_index_matches(connection, "provider_credential_one_non_terminal_operation")?
    {
        return Ok(false);
    }
    for (table, migration) in [
        ("provider_credential_versions", MIGRATION_V16),
        ("provider_credential_effect_bindings", MIGRATION_V16),
        ("provider_credential_clock_high_water", MIGRATION_V16),
        ("provider_credential_provisions", MIGRATION_V16),
        ("bootstrap_reservations", MIGRATION_V17),
        ("bootstrap_reservation_tombstones", MIGRATION_V17),
        ("bootstrap_last_observed_clock", MIGRATION_V17),
        ("projects", project_workspace_schema::MIGRATION_V18),
        ("workspaces", project_workspace_schema::MIGRATION_V18),
        (
            "root_admission_nonces",
            project_workspace_schema::MIGRATION_V18,
        ),
        (
            "project_workspace_command_receipts",
            project_workspace_schema::MIGRATION_V18,
        ),
        (
            "workspace_identity_history",
            project_workspace_schema::MIGRATION_V18,
        ),
        (
            "task_run_workspace_lineage",
            project_workspace_schema::MIGRATION_V18,
        ),
        (
            "aggregate_state_snapshots",
            replay_promotion_snapshot_schema::MIGRATION_V20,
        ),
        ("process_output", MIGRATION_V21),
        ("approvals", MIGRATION_V23),
    ] {
        if !table_sql_matches_migration(connection, table, migration)? {
            return Ok(false);
        }
    }
    if !v22_process_registry_matches(connection)? {
        return Ok(false);
    }
    if !inherited_indexes_match(connection)? {
        return Ok(false);
    }
    for (name, source) in V16_TRIGGERS.into_iter().chain(V17_TRIGGERS) {
        if !v24_trigger_matches(connection, name, source)? {
            return Ok(false);
        }
    }
    for (name, source) in [
        (
            "aggregate_state_snapshots_bind_insert",
            replay_snapshot_schema::SNAPSHOT_INSERT_TRIGGER,
        ),
        (
            "aggregate_state_snapshots_bind_update",
            replay_snapshot_schema::SNAPSHOT_UPDATE_TRIGGER,
        ),
    ] {
        if !v24_trigger_matches(connection, name, source)? {
            return Ok(false);
        }
    }
    for table in [
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
    ] {
        if !v24_table_sql_matches_migration(connection, table)? {
            return Ok(false);
        }
    }
    for (name, source) in V24_TRIGGERS {
        let expected = if V25_REPLACED_TRIGGERS.contains(&name) {
            v25_trigger(name, source)
        } else {
            source.to_owned()
        };
        if !v24_trigger_matches(connection, name, &expected)? {
            return Ok(false);
        }
    }
    Ok(true)
}

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
mod v26_trigger_catalog;
