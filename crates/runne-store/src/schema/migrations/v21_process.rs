pub(super) const MIGRATION_V21: &str = r#"
CREATE TABLE process_registry (
    process_id BLOB PRIMARY KEY CHECK(length(process_id) = 16),
    invocation_id BLOB NOT NULL CHECK(length(invocation_id) = 16),
    workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16),
    task_run_id BLOB NOT NULL CHECK(length(task_run_id) = 16),
    attempt_id BLOB NOT NULL CHECK(length(attempt_id) = 16),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 5),
    version INTEGER NOT NULL CHECK(version > 0),
    next_output_sequence INTEGER NOT NULL CHECK(next_output_sequence > 0),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    owner_id BLOB NOT NULL CHECK(length(owner_id) = 16),
    binding_attempt_id BLOB NOT NULL CHECK(length(binding_attempt_id) = 16),
    session_id BLOB NOT NULL CHECK(length(session_id) = 16),
    generation_id BLOB NOT NULL CHECK(length(generation_id) = 16),
    tree_handle BLOB NOT NULL CHECK(length(tree_handle) = 16),
    pid INTEGER NOT NULL CHECK(pid > 0),
    start_identity BLOB NOT NULL CHECK(length(start_identity) = 32),
    launch_nonce BLOB NOT NULL CHECK(length(launch_nonce) = 16),
    created_at INTEGER NOT NULL CHECK(created_at > 0),
    updated_at INTEGER NOT NULL CHECK(updated_at > 0),
    UNIQUE(workspace_id, task_run_id, attempt_id, invocation_id)
);
CREATE INDEX idx_process_registry_owner
    ON process_registry(principal_id, process_id);
CREATE TABLE process_output (
    process_id BLOB NOT NULL REFERENCES process_registry(process_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    stream INTEGER NOT NULL CHECK(stream IN (1, 2)),
    text TEXT NOT NULL CHECK(length(CAST(text AS BLOB)) BETWEEN 1 AND 65536),
    created_at INTEGER NOT NULL CHECK(created_at > 0),
    PRIMARY KEY(process_id, sequence)
);
"#;

pub(super) fn apply_v21_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V21)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (21)", [])?;
    transaction.commit()
}

pub(super) fn v21_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 21 {
        return Ok(false);
    }
    let base = replay_promotion_snapshot_schema::v20_catalog_matches(connection, true, false)?;
    let registry = table_sql_matches_migration(
        connection,
        "process_registry",
        MIGRATION_V21,
    )?;
    let output = table_sql_matches_migration(connection, "process_output", MIGRATION_V21)?;
    let index = index_matches(
        connection,
        "idx_process_registry_owner",
        "process_registry",
        &["principal_id", "process_id"],
    )?;
    Ok(base && registry && output && index)
}
