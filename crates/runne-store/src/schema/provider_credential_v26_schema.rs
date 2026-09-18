include!("provider_credential_v26_schema/constants.inc");

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
        false,
    )
}

pub(super) fn v26_predecessor_matches_with(
    connection: &Connection,
    operation_table_matches: fn(&Connection) -> SqliteResult<bool>,
    trigger_catalog_matches: fn(&Connection) -> SqliteResult<bool>,
    lineage_v37: bool,
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
        if table == "task_run_workspace_lineage" && lineage_v37 {
            // Version-strict: a v39 structure must carry the v39 lineage DDL
            // exactly — the historical v18 shape is drift, not a fallback.
            if !v39_lineage_table_matches(connection)? {
                return Ok(false);
            }
        } else if !table_sql_matches_migration(connection, table, migration)? {
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

include!("provider_credential_v26_schema/structure_helpers.inc");

mod v26_trigger_catalog;
