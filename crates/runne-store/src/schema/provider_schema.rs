use rusqlite::{
    Connection, OptionalExtension, Result as SqliteResult, Transaction, TransactionBehavior,
};

pub(super) const MIGRATION_V14: &str = r#"
ALTER TABLE provider_runtime_authority_state ADD COLUMN capability_expires_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_runtime_authority_state ADD COLUMN capability_revocation_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_runtime_authority_state ADD COLUMN capability_revocation_observed INTEGER NOT NULL DEFAULT 0
    CHECK(capability_revocation_observed IN (0, 1));
ALTER TABLE provider_runtime_authority_state ADD COLUMN approval_revocation_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_runtime_authority_state ADD COLUMN approval_revocation_observed INTEGER NOT NULL DEFAULT 0
    CHECK(approval_revocation_observed IN (0, 1));
ALTER TABLE provider_runtime_authority_state ADD COLUMN activation_binding_kind TEXT NOT NULL DEFAULT 'legacy_unbound'
    CHECK(activation_binding_kind IN ('legacy_unbound', 'protected_v2', 'external_owner_private'));
ALTER TABLE provider_runtime_authority_state ADD COLUMN activation_binding_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(length(activation_binding_digest) = 32);
ALTER TABLE provider_execution_admissions ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
ALTER TABLE provider_execution_admissions ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE provider_execution_admissions ADD COLUMN capability_grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE provider_execution_admissions ADD COLUMN capability_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_execution_admissions ADD COLUMN capability_expires_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_execution_admissions ADD COLUMN capability_revocation_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_execution_admissions ADD COLUMN capability_revocation_observed INTEGER NOT NULL DEFAULT 0
    CHECK(capability_revocation_observed IN (0, 1));
ALTER TABLE provider_execution_admissions ADD COLUMN approval_id TEXT NOT NULL DEFAULT '';
ALTER TABLE provider_execution_admissions ADD COLUMN approval_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_execution_admissions ADD COLUMN approval_expires_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_execution_admissions ADD COLUMN approval_revocation_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_execution_admissions ADD COLUMN approval_revocation_observed INTEGER NOT NULL DEFAULT 0
    CHECK(approval_revocation_observed IN (0, 1));
ALTER TABLE provider_execution_admissions ADD COLUMN activation_binding_kind TEXT NOT NULL DEFAULT 'legacy_unbound'
    CHECK(activation_binding_kind IN ('legacy_unbound', 'protected_v2', 'external_owner_private'));
ALTER TABLE provider_execution_admissions ADD COLUMN activation_binding_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(length(activation_binding_digest) = 32);
UPDATE provider_runtime_authority_state
SET active = 0, capability_expires_at = 0, capability_revocation_epoch = 0,
    capability_revocation_observed = 0, approval_expires_at = 0,
    approval_revocation_epoch = 0, approval_revocation_observed = 0,
    activation_binding_kind = 'legacy_unbound', activation_binding_digest = zeroblob(32);
"#;

pub(crate) fn apply_v14_migration<F>(conn: &Connection, install_fences: F) -> SqliteResult<()>
where
    F: FnOnce(&Transaction<'_>) -> SqliteResult<()>,
{
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V14)?;
    install_fences(&tx)?;
    tx.execute("INSERT INTO schema_version (version) VALUES (14)", [])?;
    tx.commit()
}

pub(super) const MIGRATION_V15: &str = r#"
CREATE TABLE provider_effect_starts (
    dispatch_attempt_id BLOB NOT NULL PRIMARY KEY REFERENCES provider_dispatch_attempts(attempt_id),
    provider_idempotency_key TEXT NOT NULL UNIQUE REFERENCES provider_execution_admissions(provider_idempotency_key),
    permit_id BLOB NOT NULL UNIQUE CHECK(length(permit_id) = 16),
    effect_started_at INTEGER NOT NULL,
    effect_expires_at INTEGER NOT NULL CHECK(effect_expires_at = effect_started_at + 120),
    state INTEGER NOT NULL CHECK(state = 1)
);
"#;

pub(crate) fn apply_v15_migration(conn: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V15)?;
    tx.execute("INSERT INTO schema_version (version) VALUES (15)", [])?;
    tx.commit()
}

pub(super) fn v15_matches(
    conn: &Connection,
    version: i64,
    v14_matches: bool,
) -> SqliteResult<bool> {
    if version != 15 {
        return Ok(false);
    }
    v15_base_matches(conn, v14_matches)
}

/// Checks the additive V15 table without constraining a later schema marker.
pub(super) fn v15_base_matches(conn: &Connection, v14_matches: bool) -> SqliteResult<bool> {
    if !v14_matches {
        return Ok(false);
    }
    let actual: Option<String> = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'provider_effect_starts'",
        [], |row| row.get(0),
    ).optional()?;
    let expected = MIGRATION_V15.split(';').map(str::trim).next();
    Ok(actual.is_some_and(|actual| {
        expected
            .is_some_and(|expected| super::normalize_ddl(&actual) == super::normalize_ddl(expected))
    }))
}

pub(super) fn v15_catalog_matches(conn: &Connection) -> SqliteResult<bool> {
    let mut tables = super::RELEASED_V13_TABLES.to_vec();
    tables.push("provider_effect_starts");
    super::released_catalog_matches(conn, &tables)
}

pub(super) fn v14_columns_match(
    conn: &Connection,
    version: i64,
    v12_core_matches: bool,
    v13_unchanged_provider_matches: bool,
) -> SqliteResult<bool> {
    if version != 14 {
        return Ok(false);
    }
    v14_base_matches(conn, v12_core_matches, v13_unchanged_provider_matches)
}

/// Checks the exact V14 inherited tables without constraining an additive version.
pub(super) fn v14_base_matches(
    conn: &Connection,
    v12_core_matches: bool,
    v13_unchanged_provider_matches: bool,
) -> SqliteResult<bool> {
    if !v12_core_matches || !v13_unchanged_provider_matches {
        return Ok(false);
    }
    released_v14_table_matches(conn, "provider_runtime_authority_state").and_then(|state_matches| {
        released_v14_table_matches(conn, "provider_execution_admissions")
            .map(|admission_matches| state_matches && admission_matches)
    })
}

fn released_v14_table_matches(conn: &Connection, table: &str) -> SqliteResult<bool> {
    let actual: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|actual| {
        released_v14_table_sql(table).is_some_and(|expected| {
            super::normalize_ddl(&actual) == super::normalize_ddl(&expected)
        })
    }))
}

fn released_v14_table_sql(table: &str) -> Option<String> {
    let create_prefix = format!("CREATE TABLE {table} ");
    let alter_prefix = format!("ALTER TABLE {table} ADD COLUMN ");
    let v13_table = super::MIGRATION_V13
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(&create_prefix))?
        .strip_suffix(')')?;
    let additions = MIGRATION_V14
        .split(';')
        .map(str::trim)
        .filter_map(|statement| statement.strip_prefix(&alter_prefix))
        .collect::<Vec<_>>();
    let additions = additions.join(", ");
    if table == "provider_execution_admissions" {
        let (columns, constraint) = v13_table.split_once(", FOREIGN KEY(")?;
        Some(format!("{columns}, {additions}, FOREIGN KEY({constraint})"))
    } else {
        (!additions.is_empty()).then(|| format!("{v13_table}, {additions})"))
    }
}
