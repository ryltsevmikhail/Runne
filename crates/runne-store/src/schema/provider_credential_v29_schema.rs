const V29_TABLE: &str = "provider_credential_process_attachments";
const V29_TRIGGERS: [&str; 3] = [
    "provider_credential_attachment_insert",
    "provider_credential_attachment_immutable",
    "provider_credential_attachment_no_delete",
];

pub(super) fn v29_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 29 || !v29_predecessor_matches(connection)? || !v29_catalog_matches(connection)? {
        return Ok(false);
    }
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", [V29_TABLE], |row| row.get(0),
    ).optional()?;
    if actual.is_none_or(|sql| normalize_v24_ddl(&sql) != v29_table_source()) {
        return Ok(false);
    }
    if !V29_TRIGGERS.into_iter().try_fold(true, |valid, name| {
        Ok::<bool, rusqlite::Error>(
            valid && v24_trigger_matches(connection, name, v29_trigger_source(name))?,
        )
    })? {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(marker == (29, 1, 28, 416))
}

fn v29_predecessor_matches(connection: &Connection) -> SqliteResult<bool> {
    if !v26_predecessor_matches_with(connection, v28_operation_table_matches, v29_trigger_catalog_matches)? {
        return Ok(false);
    }
    for table in [V26_ISSUANCE_EVIDENCE_TABLE, V26_CLAIM_PROVIDER_TABLE, V26_TABLE] {
        let actual: Option<String> = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", [table], |row| row.get(0),
        ).optional()?;
        if actual.is_none_or(|sql| normalize_v24_ddl(&sql) != v26_table_source(table)) {
            return Ok(false);
        }
    }
    let receipt: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_credential_completion_receipts'", [], |row| row.get(0),
    ).optional()?;
    Ok(receipt.is_some_and(|sql| {
        normalize_v24_ddl(&sql) == v28_table_source("provider_credential_completion_receipts")
    }))
}

fn v29_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    v29_catalog_matches_with_credential_operation_indexes(
        connection,
        &["provider_credential_one_non_terminal_operation"],
    )
}

fn v29_catalog_matches_with_credential_operation_indexes(
    connection: &Connection,
    credential_operation_indexes: &[&str],
) -> SqliteResult<bool> {
    let mut tables = RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts", "provider_credential_versions", "provider_credential_clock_high_water",
        "provider_credential_provisions", "provider_credential_effect_bindings", "bootstrap_reservations",
        "bootstrap_reservation_tombstones", "bootstrap_last_observed_clock", "projects", "workspaces",
        "root_admission_nonces", "project_workspace_command_receipts", "workspace_identity_history",
        "task_run_workspace_lineage", "aggregate_state_snapshots", "process_registry", "process_output",
        "approvals", "provider_credential_operations", "provider_credential_ticket_attempts",
        "provider_credential_authority_heads", "provider_credential_readiness_observations",
        "provider_credential_verification_observations", V26_ISSUANCE_EVIDENCE_TABLE,
        V26_CLAIM_PROVIDER_TABLE, V26_TABLE, "provider_credential_completion_receipts", V29_TABLE,
    ]);
    let mut indexes = RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
        "bootstrap_reservation_unexpired",
        "idx_aggregate_state_snapshots_head_position",
        "idx_process_registry_owner",
        "idx_approvals_pending",
    ]);
    indexes.extend_from_slice(credential_operation_indexes);
    released_catalog_matches_with_indexes(connection, &tables, &indexes)
}

fn v29_trigger_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    let additional = V27_TRIGGERS.map(|name| (name, v27_trigger_source(name))).into_iter()
        .chain(V28_TRIGGERS.map(|name| (name, v28_trigger_source(name))))
        .chain(V29_TRIGGERS.map(|name| (name, v29_trigger_source(name))))
        .collect::<Vec<_>>();
    v26_trigger_catalog::matches_with_additional(connection, &additional)
}

fn v29_table_source() -> String {
    let table = MIGRATION_V29.split(';').map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE TABLE {V29_TABLE}")))
        .expect("V29 attachment table is frozen");
    normalize_v24_ddl(table)
}

fn v29_trigger_source(name: &str) -> &'static str {
    let start = MIGRATION_V29.find(&format!("CREATE TRIGGER {name}")).expect("V29 trigger exists");
    let end = MIGRATION_V29[start..].find("END;").expect("V29 trigger ends") + start + 4;
    &MIGRATION_V29[start..end]
}
