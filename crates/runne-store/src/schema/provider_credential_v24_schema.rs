include!("provider_credential_v24_schema/triggers.inc");

fn v24_head_active_lifecycle_trigger() -> &'static str {
    V24_TRIGGERS
        .iter()
        .find(|(name, _)| *name == "provider_credential_head_active_lifecycle")
        .expect("V24 head lifecycle trigger exists")
        .1
}

pub(super) fn install_v24_triggers(transaction: &Transaction<'_>) -> SqliteResult<()> {
    for (_, trigger) in V24_TRIGGERS {
        transaction.execute_batch(trigger)?;
    }
    Ok(())
}

pub(super) fn v24_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 24 || !v24_predecessor_matches(connection)? || !v24_catalog_matches(connection)? {
        return Ok(false);
    }
    for table in [
        "provider_credential_operations",
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
    ] {
        if !v24_table_sql_matches_migration(connection, table)? {
            return Ok(false);
        }
    }
    for (name, expected) in V24_TRIGGERS {
        if !v24_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    v24_index_matches(connection, "provider_credential_one_non_terminal_operation")
}

fn v24_predecessor_matches(connection: &Connection) -> SqliteResult<bool> {
    let mut additional = vec![
        "aggregate_state_snapshots_bind_insert",
        "aggregate_state_snapshots_bind_update",
    ];
    additional.extend(V24_TRIGGERS.iter().map(|(name, _)| *name));
    let v18 = project_workspace_schema::v18_base_matches_with_additional_triggers(
        connection,
        &additional,
    )?;
    let v20 = table_sql_matches_migration(
        connection,
        "aggregate_state_snapshots",
        replay_promotion_snapshot_schema::MIGRATION_V20,
    )? && index_matches(
        connection,
        "idx_aggregate_state_snapshots_head_position",
        "aggregate_state_snapshots",
        &["head_global_position"],
    )? && snapshot_triggers_match(connection)?;
    let strict_v9 = is_released_strict_v9_with_v12_fence(connection)?;
    let v12 = provider_v12_core_matches(connection)?;
    let v13 = v13_unchanged_tables_match(connection)?;
    let v14 = provider_schema::v14_base_matches(connection, v12, v13)?;
    let provider_chain = v14 && provider_schema::v15_base_matches(connection, v14)?;
    let intent_digest = connection
        .prepare("PRAGMA table_info(process_registry)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<SqliteResult<Vec<_>>>()?
        .iter()
        .any(|name| name == "intent_digest");
    Ok(v18
        && v20
        && strict_v9
        && provider_chain
        && intent_digest
        && table_sql_matches_migration(connection, "approvals", MIGRATION_V23)?
        && index_matches(
            connection,
            "idx_approvals_pending",
            "approvals",
            &["principal_id", "state", "expires_at", "approval_id"],
        )?)
}

fn snapshot_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    [
        (
            "aggregate_state_snapshots_bind_insert",
            replay_snapshot_schema::SNAPSHOT_INSERT_TRIGGER,
        ),
        (
            "aggregate_state_snapshots_bind_update",
            replay_snapshot_schema::SNAPSHOT_UPDATE_TRIGGER,
        ),
    ]
    .into_iter()
    .try_fold(true, |valid, (name, expected)| {
        Ok(valid && v24_trigger_matches(connection, name, expected)?)
    })
}

fn v24_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
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

fn v24_index_matches(connection: &Connection, name: &str) -> SqliteResult<bool> {
    let expected = MIGRATION_V24
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}")));
    v24_index_matches_with_source(connection, name, expected)
}

fn v24_index_matches_with_source(
    connection: &Connection,
    name: &str,
    expected: Option<&str>,
) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_v24_ddl(&actual) == normalize_v24_ddl(expected))
    }))
}

fn v24_table_sql_matches_migration(connection: &Connection, table: &str) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V24
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE TABLE {table} ")));
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_v24_ddl(&actual) == normalize_v24_ddl(expected))
    }))
}

fn normalize_v24_ddl(ddl: &str) -> String {
    let mut normalized = String::with_capacity(ddl.len());
    let mut chars = ddl.chars().peekable();
    let mut quote = None;
    while let Some(ch) = chars.next() {
        if let Some(delimiter) = quote {
            normalized.push(ch);
            if ch == delimiter {
                if chars.peek() == Some(&delimiter) {
                    normalized.push(chars.next().unwrap());
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            normalized.push(ch);
        } else if ch == '-' && chars.peek() == Some(&'-') {
            chars.next();
            while chars.next().is_some_and(|next| next != '\n') {}
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else if !ch.is_whitespace() {
            normalized.extend(ch.to_lowercase());
        }
    }
    normalized
}

fn v24_trigger_matches(connection: &Connection, name: &str, expected: &str) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|actual| {
        normalize_sql(&actual) == normalize_sql(expected.trim().trim_end_matches(';'))
    }))
}
