pub(super) const MIGRATION_V23: &str = r#"
CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY CHECK(length(approval_id) = 36),
    task_run_id TEXT NOT NULL CHECK(length(task_run_id) = 36),
    attempt_id TEXT CHECK(attempt_id IS NULL OR length(attempt_id) = 36),
    invocation_id TEXT NOT NULL CHECK(length(invocation_id) = 36),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    action TEXT NOT NULL CHECK(length(CAST(action AS BLOB)) BETWEEN 1 AND 4096),
    resource TEXT NOT NULL CHECK(length(CAST(resource AS BLOB)) BETWEEN 1 AND 4096),
    action_digest BLOB NOT NULL CHECK(length(action_digest) = 32),
    policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
    request_version INTEGER NOT NULL CHECK(request_version > 0),
    renderer_generation INTEGER NOT NULL CHECK(renderer_generation > 0),
    expires_at INTEGER NOT NULL CHECK(expires_at > 0),
    risk_summary TEXT NOT NULL CHECK(length(CAST(risk_summary AS BLOB)) BETWEEN 1 AND 4096),
    state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 5),
    decision_command_id BLOB UNIQUE CHECK(decision_command_id IS NULL OR length(decision_command_id) = 16),
    decision_idempotency_key TEXT UNIQUE,
    decision_principal_id TEXT,
    decision INTEGER CHECK(decision IS NULL OR decision IN (1, 2)),
    decided_at INTEGER,
    updated_at INTEGER NOT NULL CHECK(updated_at > 0)
);
CREATE INDEX idx_approvals_pending ON approvals(principal_id, state, expires_at, approval_id);
"#;

pub(super) fn apply_v23_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V23)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (23)", [])?;
    transaction.commit()
}

pub(super) fn v23_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    let has_intent_digest = connection
        .prepare("PRAGMA table_info(process_registry)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<SqliteResult<Vec<_>>>()?
        .iter()
        .any(|name| name == "intent_digest");
    let base = replay_promotion_snapshot_schema::v20_base_matches(connection, false)?;
    let strict_v9 = is_released_strict_v9_with_v12_fence(connection)?;
    let catalog = replay_promotion_snapshot_schema::catalog_matches_with_approvals(
        connection,
        true,
        true,
    )?;
    let v12 = provider_v12_core_matches(connection)?;
    let v13 = v13_unchanged_tables_match(connection)?;
    let v14 = provider_schema::v14_base_matches(connection, v12, v13)?;
    let v15 = provider_schema::v15_base_matches(connection, v14)?;
    let provider_chain = v14 && v15;
    let table = table_sql_matches_migration(connection, "approvals", MIGRATION_V23)?;
    let index = index_matches(
        connection,
        "idx_approvals_pending",
        "approvals",
        &["principal_id", "state", "expires_at", "approval_id"],
    )?;
    if version != 23
        || !base
        || !strict_v9
        || !catalog
        || !provider_chain
        || !has_intent_digest
    {
        return Ok(false);
    }
    Ok(table && index)
}
