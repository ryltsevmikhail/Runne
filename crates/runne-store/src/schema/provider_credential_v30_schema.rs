const V30_TRIGGERS: [&str; 4] = [
    "provider_credential_verification_binding_insert",
    "provider_credential_verification_binding_immutable",
    "provider_credential_verification_binding_complete",
    "provider_credential_remote_verification_binding",
];

mod trigger_catalog;

fn v30_trigger_source(name: &str) -> &'static str {
    trigger_catalog::source(name)
}

pub(super) fn v30_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 30 || !v30_predecessor_matches(connection)? || !v30_columns_match(connection)? {
        return Ok(false);
    }
    if !V30_TRIGGERS.into_iter().try_fold(true, |valid, name| {
        Ok::<bool, rusqlite::Error>(
            valid && v24_trigger_matches(connection, name, trigger_catalog::source(name))?,
        )
    })? {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (30, 1, 29, 446) | (30, 1, 30, 465)))
}

pub(super) fn v30_predecessor_matches(connection: &Connection) -> SqliteResult<bool> {
    v30_predecessor_matches_with(
        connection,
        &v25_trigger(
            "provider_credential_operation_insert_prepared",
            V24_TRIGGERS
                .iter()
                .find(|(name, _)| *name == "provider_credential_operation_insert_prepared")
                .expect("V24 insert trigger exists")
                .1,
        ),
    )
}

pub(super) fn v30_predecessor_matches_with(
    connection: &Connection,
    insert_trigger: &str,
) -> SqliteResult<bool> {
    v30_predecessor_matches_with_successors(
        connection,
        insert_trigger,
        v24_head_active_lifecycle_trigger(),
        &["provider_credential_one_non_terminal_operation"],
        &CredentialSchemaExtensions::default(),
        false,
        false,
    )
}

pub(super) fn v30_predecessor_matches_with_v32(
    connection: &Connection,
    insert_trigger: &str,
    head_trigger: &str,
) -> SqliteResult<bool> {
    v30_predecessor_matches_with_successors(
        connection,
        insert_trigger,
        head_trigger,
        true,
        &CredentialSchemaExtensions::default(),
        false,
        false,
    )
}

fn v30_predecessor_matches_with_successors(
    connection: &Connection,
    insert_trigger: &str,
    head_trigger: &str,
    operation_indexes: &[&str],
    extensions: &CredentialSchemaExtensions<'_>,
    allows_v36_project_receipt: bool,
    lineage_v37: bool,
) -> SqliteResult<bool> {
    if !v30_v26_base_matches_with(
        connection,
        insert_trigger,
        head_trigger,
        operation_indexes,
        extensions,
        allows_v36_project_receipt,
        lineage_v37,
    )? || !v29_catalog_matches_with_extensions(
        connection,
        operation_indexes,
        extensions,
    )? {
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
    let receipt: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_credential_completion_receipts'", [], |row| row.get(0),
    ).optional()?;
    Ok(receipt.is_some_and(|sql| {
        normalize_v24_ddl(&sql) == v28_table_source("provider_credential_completion_receipts")
    }))
}

fn v30_v26_base_matches_with(
    connection: &Connection,
    insert_trigger: &str,
    head_trigger: &str,
    operation_indexes: &[&str],
    extensions: &CredentialSchemaExtensions<'_>,
    allows_v36_project_receipt: bool,
    lineage_v37: bool,
) -> SqliteResult<bool> {
    if !v18_global_trigger_matches(connection)?
        || !trigger_catalog::matches_with(connection, insert_trigger, head_trigger, extensions)?
    {
        return Ok(false);
    }
    let v12 = provider_v12_core_matches(connection)?;
    let is_v37 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get::<_, i64>(0),
    )? == 37;
    let v13 = if is_v37 {
        v13_unchanged_tables_match_for_v37(connection)?
    } else {
        v13_unchanged_tables_match(connection)?
    };
    let v14 = if is_v37 {
        provider_schema::v14_base_matches_for_v37(
            connection,
            v12,
            v13 && v37_accounting_tables_match(connection)?,
        )?
    } else {
        provider_schema::v14_base_matches(connection, v12, v13)?
    };
    if !v14
        || !provider_schema::v15_base_matches(connection, v14)?
        || !v28_operation_table_matches(connection)?
        || !(if operation_indexes == v32_operation_index_names() {
            v32_operation_indexes_match(connection)?
        } else if operation_indexes == v35_operation_index_names() {
            v35_operation_indexes_match(connection)?
        } else {
            v24_index_matches(connection, "provider_credential_one_non_terminal_operation")?
        })
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
        } else if !(table_sql_matches_migration(connection, table, migration)?
            || (allows_v36_project_receipt
                && table == "project_workspace_command_receipts"
                && project_workspace_schema::v36_receipt_table_matches(connection)?))
        {
            return Ok(false);
        }
    }
    if !v22_process_registry_matches(connection)?
        || !(if operation_indexes == v32_operation_index_names() {
            inherited_indexes_match_with_v32_operation_indexes(connection)?
        } else {
            inherited_indexes_match_with_operation_indexes(connection, operation_indexes)?
        })
    {
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
    ] {
        if !v24_table_sql_matches_migration(connection, table)? {
            return Ok(false);
        }
    }
    for (name, source) in V24_TRIGGERS {
        let expected = if let Some((_, replacement)) =
            extensions.replacements.iter().find(|(n, _)| *n == name)
        {
            (*replacement).to_owned()
        } else if name == "provider_credential_operation_insert_prepared" {
            insert_trigger.to_owned()
        } else if name == "provider_credential_head_active_lifecycle" {
            head_trigger.to_owned()
        } else if V25_REPLACED_TRIGGERS.contains(&name) {
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

fn v30_columns_match(connection: &Connection) -> SqliteResult<bool> {
    let columns = connection
        .prepare("PRAGMA table_info(provider_credential_verification_observations)")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(columns.ends_with(&[
        ("readiness_revision".to_owned(), "INTEGER".to_owned()),
        ("release_tuple_digest".to_owned(), "BLOB".to_owned()),
    ]))
}
