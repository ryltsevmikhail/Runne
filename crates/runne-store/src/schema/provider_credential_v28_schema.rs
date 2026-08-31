const V28_TRIGGERS: [&str; 5] = [
    "provider_credential_qualified_release_tuple_insert",
    "provider_credential_qualified_release_tuple_immutable",
    "provider_credential_completion_receipt_insert",
    "provider_credential_completion_receipt_append_only",
    "provider_credential_completion_receipt_no_delete",
];

pub(super) fn v28_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 28 || !v28_predecessor_matches(connection)? {
        return Ok(false);
    }
    for table in ["provider_credential_operations", "provider_credential_completion_receipts"] {
        let actual: Option<String> = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        ).optional()?;
        if actual.is_none_or(|sql| normalize_v24_ddl(&sql) != v28_table_source(table)) {
            return Ok(false);
        }
    }
    for name in V28_TRIGGERS {
        if !v24_trigger_matches(connection, name, v28_trigger_source(name))? {
            return Ok(false);
        }
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (28, 1, 27, 387) | (28, 1, 28, 406)))
}

fn v28_predecessor_matches(connection: &Connection) -> SqliteResult<bool> {
    Ok(v26_predecessor_matches_with(connection, v28_operation_table_matches, v28_trigger_catalog_matches)?
        && v28_catalog_matches(connection)?
        && [V26_ISSUANCE_EVIDENCE_TABLE, V26_CLAIM_PROVIDER_TABLE, V26_TABLE]
            .into_iter()
            .try_fold(true, |matches, table| {
                let actual: Option<String> = connection.query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    [table], |row| row.get(0),
                ).optional()?;
                Ok::<_, rusqlite::Error>(
                    matches
                        && actual.is_some_and(|sql| {
                            normalize_v24_ddl(&sql) == v26_table_source(table)
                        }),
                )
            })?)
}

fn v28_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
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
        "provider_credential_completion_receipts",
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

fn v28_operation_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_credential_operations'",
        [], |row| row.get(0),
    ).optional()?;
    Ok(actual.is_some_and(|sql| normalize_v24_ddl(&sql) == v28_table_source("provider_credential_operations")))
}

fn v28_trigger_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    let additional = V27_TRIGGERS
        .map(|name| (name, v27_trigger_source(name)))
        .into_iter()
        .chain(V28_TRIGGERS.map(|name| (name, v28_trigger_source(name))))
        .collect::<Vec<_>>();
    v26_trigger_catalog::matches_with_additional(connection, &additional)
}

fn v28_table_source(table: &str) -> String {
    match table {
        "provider_credential_operations" => v27_operation_table_source().replacen(
            ",check((allocated_credential_version",
            ",qualified_release_tuple_digestblobcheck(qualified_release_tuple_digestisnullorlength(qualified_release_tuple_digest)=32),check((allocated_credential_version",
            1,
        ),
        "provider_credential_completion_receipts" => {
            normalize_v24_ddl(v28_source("CREATE TABLE provider_credential_completion_receipts"))
                .trim_end_matches(';')
                .to_owned()
        }
        _ => unreachable!("V28 table must be catalogued"),
    }
}

fn v28_trigger_source(name: &str) -> &'static str {
    v28_source(&format!("CREATE TRIGGER {name}"))
}

fn v28_source(start: &str) -> &'static str {
    let start = MIGRATION_V28.find(start).expect("V28 object exists");
    let source = &MIGRATION_V28[start..];
    let end = if source.starts_with("CREATE TRIGGER") {
        source.find("END;").expect("V28 trigger ends") + 4
    } else {
        source.find(';').expect("V28 table ends") + 1
    };
    &source[..end]
}
