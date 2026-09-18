use rusqlite::{
    Connection, OptionalExtension, Result as SqliteResult, Transaction, TransactionBehavior,
};

mod validation;

pub(super) const MIGRATION_V18: &str = r#"
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

pub(super) const GLOBAL_COMMAND_RECEIPT_TRIGGER: &str = r#"
CREATE TRIGGER global_command_id_from_command_receipts
BEFORE INSERT ON command_receipts
WHEN EXISTS(SELECT 1 FROM project_workspace_command_receipts
            WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
"#;
pub(super) const GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER: &str = r#"
CREATE TRIGGER global_command_id_from_project_workspace_receipts
BEFORE INSERT ON project_workspace_command_receipts
WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id = NEW.command_id)
BEGIN SELECT RAISE(ABORT, 'global command id collision'); END;
"#;

pub(super) const MIGRATION_V36: &str = r#"
CREATE TABLE project_workspace_command_receipts_v36 (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 8),
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

pub(super) fn apply_v36_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(
        "DROP TRIGGER IF EXISTS global_command_id_from_command_receipts;
         DROP TRIGGER IF EXISTS global_command_id_from_project_workspace_receipts;",
    )?;
    transaction.execute_batch(MIGRATION_V36)?;
    transaction.execute_batch(
        "INSERT INTO project_workspace_command_receipts_v36
         SELECT * FROM project_workspace_command_receipts;
         DROP TABLE project_workspace_command_receipts;
         ALTER TABLE project_workspace_command_receipts_v36
         RENAME TO project_workspace_command_receipts;",
    )?;
    for operation in ["insert", "update", "delete"] {
        transaction.execute_batch(
            &super::v12_fence_trigger("project_workspace_command_receipts", operation).1,
        )?;
    }
    transaction.execute_batch(GLOBAL_COMMAND_RECEIPT_TRIGGER)?;
    transaction.execute_batch(GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (36)", [])?;
    transaction.commit()
}

pub(super) fn v36_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 36 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let inherited = v36_structure_matches(connection)?;
    let receipts = v36_receipt_table_matches(connection)?;
    let triggers = validation::global_command_triggers_match(connection)?;
    Ok(matches!(marker, (36, 1, 35, 647) | (36, 1, 36, 666)) && inherited && receipts && triggers)
}

pub(super) fn v36_structure_matches(connection: &Connection) -> SqliteResult<bool> {
    super::v35_structure_matches_with_v36_receipt(connection, true, false).and_then(|inherited| {
        Ok(inherited
            && v36_receipt_table_matches(connection)?
            && validation::global_command_triggers_match(connection)?)
    })
}

pub(super) fn v36_receipt_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            ["project_workspace_command_receipts"],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V36
        .split(';')
        .map(str::trim)
        .find(|statement| {
            statement.starts_with("CREATE TABLE project_workspace_command_receipts_v36 ")
        })
        .map(|statement| {
            statement.replace(
                "CREATE TABLE project_workspace_command_receipts_v36",
                "CREATE TABLE \"project_workspace_command_receipts\"",
            )
        });
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| {
            super::normalize_ddl(&actual) == super::normalize_ddl(&expected)
        })
    }))
}

#[cfg(test)]
pub(crate) fn restore_v18_project_workspace_receipt_for_test(
    connection: &Connection,
) -> SqliteResult<()> {
    let receipt = MIGRATION_V18
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE TABLE project_workspace_command_receipts "))
        .expect("V18 project receipt is frozen");
    let temporary = receipt.replace(
        "CREATE TABLE project_workspace_command_receipts",
        "CREATE TABLE project_workspace_command_receipts_v18",
    );
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(&format!("DROP TRIGGER global_command_id_from_command_receipts; DROP TRIGGER global_command_id_from_project_workspace_receipts; {temporary}; INSERT INTO project_workspace_command_receipts_v18 SELECT * FROM project_workspace_command_receipts; DROP TABLE project_workspace_command_receipts; {receipt}; INSERT INTO project_workspace_command_receipts SELECT * FROM project_workspace_command_receipts_v18; DROP TABLE project_workspace_command_receipts_v18;"))?;
    for operation in ["insert", "update", "delete"] {
        transaction.execute_batch(
            &super::v12_fence_trigger("project_workspace_command_receipts", operation).1,
        )?;
    }
    transaction.execute_batch(GLOBAL_COMMAND_RECEIPT_TRIGGER)?;
    transaction.execute_batch(GLOBAL_PROJECT_WORKSPACE_RECEIPT_TRIGGER)?;
    transaction.commit()
}

pub(super) fn apply_v18_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V18)?;
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
    transaction.execute("INSERT INTO schema_version (version) VALUES (18)", [])?;
    transaction.commit()
}

pub(super) fn v18_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 18 {
        return Ok(false);
    }
    if !v18_base_matches(connection)? {
        return Ok(false);
    }
    let mut tables = super::RELEASED_V13_TABLES.to_vec();
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
    ]);
    let mut indexes = super::RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
        "bootstrap_reservation_unexpired",
    ]);
    super::released_catalog_matches_with_indexes(connection, &tables, &indexes)
}

pub(super) fn v18_base_matches(connection: &Connection) -> SqliteResult<bool> {
    v18_base_matches_with_additional_triggers(connection, &[])
}

pub(super) fn v18_base_matches_with_additional_triggers(
    connection: &Connection,
    additional: &[&str],
) -> SqliteResult<bool> {
    let mut allowed_triggers = vec![
        "global_command_id_from_command_receipts",
        "global_command_id_from_project_workspace_receipts",
    ];
    allowed_triggers.extend_from_slice(additional);
    let inherited = super::released_v17_base_matches_with_additional_triggers(
        connection,
        18,
        &allowed_triggers,
    )?;
    if !inherited {
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
            valid && super::table_sql_matches_migration(connection, table, MIGRATION_V18)?,
        )
    })?;
    Ok(tables_match && validation::global_command_triggers_match(connection)?)
}
