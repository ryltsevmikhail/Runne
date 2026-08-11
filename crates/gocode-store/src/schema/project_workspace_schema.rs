use rusqlite::{
    Connection, OptionalExtension, Result as SqliteResult, Transaction, TransactionBehavior,
};

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
    project_id BLOB NOT NULL CHECK(length(project_id) = 16),
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
    workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16),
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
CREATE TABLE workspace_identity_history (
    workspace_id BLOB PRIMARY KEY CHECK(length(workspace_id) = 16),
    project_id BLOB CHECK(project_id IS NULL OR length(project_id) = 16),
    principal_id TEXT CHECK(principal_id IS NULL OR length(principal_id) BETWEEN 1 AND 256),
    classification TEXT NOT NULL CHECK(classification IN ('canonical', 'legacy_unbound')),
    CHECK((classification = 'canonical' AND project_id IS NOT NULL AND principal_id IS NOT NULL)
       OR (classification = 'legacy_unbound' AND project_id IS NULL AND principal_id IS NULL))
);
CREATE TABLE task_run_workspace_lineage (
    taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id) = 16),
    workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16),
    project_id BLOB CHECK(project_id IS NULL OR length(project_id) = 16),
    classification TEXT NOT NULL CHECK(classification IN ('canonical', 'legacy_unbound')),
    origin_command_id BLOB NOT NULL UNIQUE CHECK(length(origin_command_id) = 16),
    origin_operation INTEGER NOT NULL CHECK(origin_operation IN (1, 18)),
    CHECK((classification = 'canonical' AND project_id IS NOT NULL) OR
          (classification = 'legacy_unbound' AND project_id IS NULL))
);
"#;

const GLOBAL_COMMAND_RECEIPT_TRIGGER: &str = r#"
CREATE TRIGGER global_command_id_from_command_receipts
BEFORE INSERT ON command_receipts
WHEN EXISTS(SELECT 1 FROM project_workspace_command_receipts
            WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
"#;
const GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER: &str = r#"
CREATE TRIGGER global_command_id_from_project_workspace_receipts
BEFORE INSERT ON project_workspace_command_receipts
WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
"#;

pub(super) fn apply_v16_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V16)?;
    super::project_workspace_backfill::backfill_taskrun_lineage(&transaction)?;
    transaction.execute(
        "INSERT INTO workspace_identity_history
         (workspace_id, project_id, principal_id, classification)
         SELECT DISTINCT workspace_id, NULL, NULL, 'legacy_unbound'
         FROM task_run_workspace_lineage WHERE classification = 'legacy_unbound'",
        [],
    )?;
    transaction.execute_batch(GLOBAL_COMMAND_RECEIPT_TRIGGER)?;
    transaction.execute_batch(GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER)?;
    super::install_missing_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (16)", [])?;
    transaction.commit()
}

pub(super) fn v16_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 16 {
        return Ok(false);
    }
    let v12 = super::provider_v12_core_matches(connection)?
        && super::v12_fence_triggers_match_with_additional(
            connection,
            &[
                "global_command_id_from_command_receipts",
                "global_command_id_from_project_workspace_receipts",
            ],
        )?;
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
        "workspace_identity_history",
        "task_run_workspace_lineage",
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
        "workspace_identity_history",
        "task_run_workspace_lineage",
    ]);
    Ok(tables_match
        && global_command_triggers_match(connection)?
        && super::released_catalog_matches(connection, &tables)?)
}

fn global_command_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    [
        (
            "global_command_id_from_command_receipts",
            GLOBAL_COMMAND_RECEIPT_TRIGGER,
        ),
        (
            "global_command_id_from_project_workspace_receipts",
            GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER,
        ),
    ]
    .into_iter()
    .try_fold(true, |valid, (name, expected)| {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(valid
            && actual.is_some_and(|sql| {
                super::normalize_sql(expected.trim().trim_end_matches(';'))
                    == super::normalize_sql(&sql)
            }))
    })
}
