//! Versioned SQLite schema. The catalog is installation metadata —
//! never TaskRun authority.

use crate::error::StoreError;
use rusqlite::Connection;

pub const SCHEMA_VERSION: i64 = 1;

pub fn init(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS store_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS upload_sessions (
            artifact_digest TEXT PRIMARY KEY,
            declared_len INTEGER NOT NULL,
            committed_offset INTEGER NOT NULL,
            prefix_sha TEXT NOT NULL,
            state TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            manifest_json TEXT NOT NULL DEFAULT '',
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS candidates (
            manifest_digest TEXT PRIMARY KEY,
            manifest_json TEXT NOT NULL,
            model_id TEXT NOT NULL,
            model_revision TEXT NOT NULL,
            license TEXT NOT NULL,
            artifact_digest TEXT NOT NULL,
            byte_len INTEGER NOT NULL,
            blob_ref TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS installations (
            manifest_digest TEXT PRIMARY KEY,
            model_id TEXT NOT NULL,
            model_revision TEXT NOT NULL,
            license TEXT NOT NULL,
            artifact_digest TEXT NOT NULL,
            byte_len INTEGER NOT NULL,
            blob_ref TEXT NOT NULL,
            active_refs INTEGER NOT NULL DEFAULT 0,
            license_acceptance_digest TEXT NOT NULL,
            admitted_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tombstones (
            manifest_digest TEXT PRIMARY KEY,
            blob_ref TEXT NOT NULL,
            cleanup_done INTEGER NOT NULL DEFAULT 0,
            removed_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS backend_compat (
            manifest_digest TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            result TEXT NOT NULL,
            at INTEGER NOT NULL,
            PRIMARY KEY (manifest_digest, profile_id)
        );
        "#,
    )
    .map_err(StoreError::from)?;
    conn.execute(
        "INSERT INTO store_meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO NOTHING",
        [SCHEMA_VERSION.to_string()],
    )
    .map_err(StoreError::from)?;
    migrate(conn)?;
    Ok(())
}

/// Additive migrations. `matrix_*` columns bind an installation to a
/// qualification-matrix entry (Plan Task 22); empty = unqualified
/// install, which cannot back a capability claim.
fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let mut stmt = conn.prepare("PRAGMA table_info(installations)")?;
    let existing: std::collections::BTreeSet<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|c| c.ok())
        .collect();
    drop(stmt);
    for (column, ddl) in [
        (
            "matrix_revision",
            "ALTER TABLE installations ADD COLUMN matrix_revision TEXT NOT NULL DEFAULT ''",
        ),
        (
            "matrix_entry_id",
            "ALTER TABLE installations ADD COLUMN matrix_entry_id TEXT NOT NULL DEFAULT ''",
        ),
        (
            "matrix_evidence",
            "ALTER TABLE installations ADD COLUMN matrix_evidence TEXT NOT NULL DEFAULT ''",
        ),
    ] {
        if !existing.contains(column) {
            conn.execute_batch(ddl).map_err(StoreError::from)?;
        }
    }
    Ok(())
}

pub fn check_version(conn: &Connection) -> Result<(), StoreError> {
    let v: String = conn
        .query_row(
            "SELECT value FROM store_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)?;
    if v.parse::<i64>() != Ok(SCHEMA_VERSION) {
        return Err(StoreError::Schema(format!("schema version {v}")));
    }
    Ok(())
}
