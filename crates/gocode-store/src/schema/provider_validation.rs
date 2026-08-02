const CANONICAL_PROVIDER_PREPARED_V12_SQL: &str = "CREATE TABLE provider_prepared_requests (call_id BLOB PRIMARY KEY CHECK(length(call_id) = 16), prepared_digest BLOB NOT NULL CHECK(length(prepared_digest) = 32), render_digest BLOB NOT NULL CHECK(length(render_digest) = 32), profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32), record_digest BLOB NOT NULL CHECK(length(record_digest) = 32), call_digest_version INTEGER NOT NULL DEFAULT 1 CHECK(call_digest_version IN (1, 2)))";

type SchemaUpgradeFenceRow = (i64, i64, Option<String>, Option<Vec<u8>>, i64, i64, i64);

fn is_released_provider_v12(conn: &Connection, version: i64) -> SqliteResult<bool> {
    Ok(version == 12
        && provider_v12_core_matches(conn)?
        && v12_fence_triggers_match(conn)?
        && released_catalog_matches(conn, &RELEASED_V12_TABLES)?)
}

fn provider_v12_core_matches(conn: &Connection) -> SqliteResult<bool> {
    let fence: Option<SchemaUpgradeFenceRow> = conn.query_row("SELECT id, source_version, snapshot_filename, snapshot_digest, baseline_event_next_position, baseline_provider_prepared_count, baseline_provider_attempt_count FROM schema_upgrade_fence WHERE id = 1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))).optional()?;
    let valid_fence = fence.is_some_and(
        |(id, source, filename, digest, event, prepared, attempts)| {
            let snapshot = match (filename, digest) {
                (None, None) => true,
                (Some(filename), Some(digest)) => {
                    safe_snapshot_filename(&filename) && digest.len() == 32
                }
                _ => false,
            };
            id == 1 && source == 11 && event > 0 && prepared >= 0 && attempts >= 0 && snapshot
        },
    );
    let latch_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_upgrade_write_latch",
        [],
        |row| row.get(0),
    )?;
    let latch_valid: bool = conn.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM schema_upgrade_write_latch WHERE id != 1 OR closed != 1)",
        [],
        |row| row.get(0),
    )?;
    Ok(is_released_strict_v9_with_v12_fence(conn)?
        && table_sql_matches(
            conn,
            "provider_prepared_requests",
            CANONICAL_PROVIDER_PREPARED_V12_SQL,
        )?
        && table_sql_matches_migration(conn, "provider_dispatch_attempts", MIGRATION_V12)?
        && table_sql_matches_migration(conn, "schema_upgrade_fence", MIGRATION_V12)?
        && table_sql_matches_migration(conn, "schema_upgrade_write_latch", MIGRATION_V12)?
        && table_sql_matches_migration(conn, "provider_effect_authorities", MIGRATION_V11)?
        && valid_fence
        && latch_count <= 1
        && latch_valid)
}

fn is_released_provider_v13(conn: &Connection, version: i64) -> SqliteResult<bool> {
    Ok(version == 13
        && provider_v12_core_matches(conn)?
        && v13_tables_match(conn)?
        && v12_fence_triggers_match(conn)?
        && released_catalog_matches(conn, &RELEASED_V13_TABLES)?)
}

fn v13_tables_match(conn: &Connection) -> SqliteResult<bool> {
    [
        "provider_runtime_authority_state",
        "provider_execution_admissions",
        "provider_budget_reservations",
        "provider_journal_key_refs",
        "provider_encryption_nonces",
        "provider_poll_flights",
        "provider_stream_journal",
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ]
    .into_iter()
    .try_fold(true, |matches, table| {
        Ok(matches && table_sql_matches_migration(conn, table, MIGRATION_V13)?)
    })
}

fn v13_unchanged_tables_match(conn: &Connection) -> SqliteResult<bool> {
    [
        "provider_budget_reservations",
        "provider_journal_key_refs",
        "provider_encryption_nonces",
        "provider_poll_flights",
        "provider_stream_journal",
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ]
    .into_iter()
    .try_fold(true, |matches, table| {
        Ok(matches && table_sql_matches_migration(conn, table, MIGRATION_V13)?)
    })
}

fn is_released_provider_v14(conn: &Connection, version: i64) -> SqliteResult<bool> {
    Ok(provider_schema::v14_columns_match(
        conn,
        version,
        provider_v12_core_matches(conn)?,
        v13_unchanged_tables_match(conn)?,
    )? && v12_fence_triggers_match(conn)?
        && (version != 14 || released_catalog_matches(conn, &RELEASED_V13_TABLES)?))
}

fn is_released_provider_v15(conn: &Connection, version: i64) -> SqliteResult<bool> {
    let v12 = provider_v12_core_matches(conn)? && v12_fence_triggers_match(conn)?;
    let v13 = v13_unchanged_tables_match(conn)?;
    let v14 = provider_schema::v14_base_matches(conn, v12, v13)?;
    let v15 = provider_schema::v15_matches(conn, version, v14)?;
    let catalog = provider_schema::v15_catalog_matches(conn)?;
    Ok(v15 && catalog)
}

const RELEASED_V12_TABLES: [&str; 34] = [
    "_authority",
    "_daemon_info",
    "_replay_subscriptions",
    "aggregate_streams",
    "command_receipts",
    "consumption_intents",
    "cutover_manifests",
    "event_log_state",
    "events",
    "migration_audit",
    "migration_evidence",
    "migration_plans",
    "migration_receipts",
    "migration_reports",
    "migration_transitions",
    "provider_dispatch_attempts",
    "provider_effect_authorities",
    "provider_prepared_requests",
    "retirement_manifests",
    "rollback_manifests",
    "routing_dispatch_intents",
    "routing_head",
    "routing_snapshots",
    "runtime_bindings",
    "schema_lineage",
    "schema_upgrade_fence",
    "schema_upgrade_write_latch",
    "schema_version",
    "security_audit_pre_effect",
    "security_authorization_decisions",
    "security_budget_consumptions",
    "security_dispatch_intents",
    "security_permit_claims",
    "verification_evidence",
];

const RELEASED_V13_TABLES: [&str; 43] = [
    "_authority",
    "_daemon_info",
    "_replay_subscriptions",
    "aggregate_streams",
    "command_receipts",
    "consumption_intents",
    "cutover_manifests",
    "event_log_state",
    "events",
    "migration_audit",
    "migration_evidence",
    "migration_plans",
    "migration_receipts",
    "migration_reports",
    "migration_transitions",
    "provider_accounting_settlements",
    "provider_budget_reservations",
    "provider_dispatch_attempts",
    "provider_effect_authorities",
    "provider_encryption_nonces",
    "provider_execution_admissions",
    "provider_journal_key_refs",
    "provider_poll_flights",
    "provider_prepared_requests",
    "provider_runtime_authority_state",
    "provider_stream_journal",
    "provider_terminal_outbox",
    "retirement_manifests",
    "rollback_manifests",
    "routing_dispatch_intents",
    "routing_head",
    "routing_snapshots",
    "runtime_bindings",
    "schema_lineage",
    "schema_upgrade_fence",
    "schema_upgrade_write_latch",
    "schema_version",
    "security_audit_pre_effect",
    "security_authorization_decisions",
    "security_budget_consumptions",
    "security_dispatch_intents",
    "security_permit_claims",
    "verification_evidence",
];

pub(super) const RELEASED_V12_EXPLICIT_INDEXES: &[&str] = &[
    "idx_evidence_run",
    "idx_events_aggregate_sequence",
    "idx_migration_evidence_plan",
    "idx_migration_plans_plan_cycle",
    "idx_migration_transitions_plan",
    "idx_receipts_scope_key",
];

fn released_catalog_matches(conn: &Connection, expected_tables: &[&str]) -> SqliteResult<bool> {
    let actual = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?.query_map([], |row| row.get::<_, String>(0))?.collect::<SqliteResult<Vec<_>>>()?;
    let mut expected = expected_tables.to_vec();
    expected.sort_unstable();
    if actual
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        return Ok(false);
    }
    let actual_indexes = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<SqliteResult<Vec<_>>>()?;
    let mut expected_indexes = RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    expected_indexes.sort_unstable();
    if actual_indexes
        .iter()
        .map(String::as_str)
        .ne(expected_indexes.iter().copied())
    {
        return Ok(false);
    }
    let views: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view'",
        [],
        |row| row.get(0),
    )?;
    Ok(views == 0)
}
