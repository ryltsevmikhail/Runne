use rusqlite::{Connection, Result as SqliteResult, Transaction, TransactionBehavior};

pub(super) const MIGRATION_V16: &str = r#"
CREATE TABLE projects (
    project_id BLOB PRIMARY KEY CHECK(length(project_id) = 16),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 256),
    version INTEGER NOT NULL CHECK(version > 0),
    archived INTEGER NOT NULL CHECK(archived IN (0, 1))
);
CREATE TABLE workspaces (
    workspace_id BLOB PRIMARY KEY CHECK(length(workspace_id) = 16),
    project_id BLOB NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    display_name TEXT NOT NULL CHECK(length(CAST(display_name AS BLOB)) BETWEEN 1 AND 256),
    version INTEGER NOT NULL CHECK(version > 0),
    open INTEGER NOT NULL CHECK(open IN (0, 1)),
    live INTEGER NOT NULL DEFAULT 1 CHECK(live IN (0, 1))
);
CREATE TABLE root_admission_nonces (
    runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
    nonce BLOB NOT NULL CHECK(length(nonce) = 16),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    workspace_id BLOB NOT NULL REFERENCES workspaces(workspace_id),
    expected_version INTEGER NOT NULL CHECK(expected_version > 0),
    admission_digest BLOB NOT NULL UNIQUE CHECK(length(admission_digest) = 32),
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY(runtime_authority_id, nonce)
);
CREATE TABLE project_workspace_command_receipts (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 7),
    aggregate_kind INTEGER NOT NULL CHECK(aggregate_kind IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    idempotency_key TEXT NOT NULL CHECK(length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256),
    semantic_fingerprint BLOB NOT NULL CHECK(length(semantic_fingerprint) = 32),
    outcome BLOB NOT NULL CHECK(length(outcome) BETWEEN 1 AND 4096),
    committed_at INTEGER NOT NULL,
    UNIQUE(runtime_authority_id, principal_id, operation, aggregate_kind,
           aggregate_id, idempotency_key)
);
"#;

pub(super) fn apply_v16_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V16)?;
    super::install_missing_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (16)", [])?;
    transaction.commit()
}

pub(super) fn v16_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 16 {
        return Ok(false);
    }
    let v12 = super::provider_v12_core_matches(connection)?
        && super::v12_fence_triggers_match(connection)?;
    let v13 = super::v13_unchanged_tables_match(connection)?;
    let v14 = super::provider_schema::v14_base_matches(connection, v12, v13)?;
    let v15 = super::provider_schema::v15_matches(connection, 15, v14)?;
    if !v15 {
        return Ok(false);
    }
    let tables_match = [
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
    ]
    .into_iter()
    .try_fold(true, |valid, table| {
        Ok::<bool, rusqlite::Error>(
            valid && super::table_sql_matches_migration(connection, table, MIGRATION_V16)?,
        )
    })?;
    let mut tables = super::RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
    ]);
    Ok(tables_match && super::released_catalog_matches(connection, &tables)?)
}
