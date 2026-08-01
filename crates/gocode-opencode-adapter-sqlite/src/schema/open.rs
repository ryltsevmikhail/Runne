
use std::path::Path;

use rusqlite::{Connection, Result as SqliteResult, TransactionBehavior};

/// Current schema version for the binding database.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

const SCHEMA_VERSION_DDL: &str = r#"
CREATE TABLE gocode_session_binding_schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"#;

const MIGRATION_V1: &str = r#"
CREATE TABLE session_bindings (
    session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 256),
    profile_id TEXT NOT NULL CHECK(length(profile_id) BETWEEN 1 AND 256),
    profile_revision INTEGER NOT NULL CHECK(profile_revision BETWEEN 0 AND 65535),
    runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
    conversation_id BLOB NOT NULL CHECK(length(conversation_id) = 16),
    workspace_id BLOB NOT NULL CHECK(length(workspace_id) = 16),
    command_id BLOB NOT NULL UNIQUE CHECK(length(command_id) = 16),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint) = 32),
    context_codec_version INTEGER NOT NULL,
    context_snapshot BLOB NOT NULL CHECK(length(context_snapshot) <= 65536),
    response_codec_version INTEGER NOT NULL,
    response_snapshot BLOB CHECK(response_snapshot IS NULL OR length(response_snapshot) <= 65536),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    status TEXT NOT NULL CHECK(status IN ('pending', 'committed')),
    PRIMARY KEY (session_id, profile_id, profile_revision, runtime_authority_id),
    CHECK ((status = 'pending' AND response_snapshot IS NULL) OR
           (status = 'committed' AND response_snapshot IS NOT NULL))
);
CREATE INDEX idx_session_bindings_recovery
    ON session_bindings(runtime_authority_id, status, created_at,
                        session_id, profile_id, profile_revision);
CREATE TABLE gocode_session_binding_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    last_created_at INTEGER NOT NULL CHECK(last_created_at >= 0)
);
INSERT INTO gocode_session_binding_state(singleton, last_created_at) VALUES (1, 0);
"#;

/// Opens a single SQLite connection with required durability and safety pragmas.
pub fn open_with_pragmas(path: &Path) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;",
    )?;
    #[cfg(target_os = "macos")]
    conn.execute_batch("PRAGMA fullfsync = ON;")?;
    harden_permissions(path)?;
    verify_pragmas(&conn)?;
    Ok(conn)
}

#[cfg(unix)]
/// Enforces owner-only access on the database and SQLite sidecars when present.
pub fn harden_permissions(path: &Path) -> SqliteResult<()> {
    use std::os::unix::fs::PermissionsExt;
    if path == Path::new(":memory:") || path.to_string_lossy().starts_with("file:") {
        return Ok(());
    }
    for candidate in [
        path.to_path_buf(),
        Path::new(&format!("{}-wal", path.display())).to_path_buf(),
        Path::new(&format!("{}-shm", path.display())).to_path_buf(),
    ] {
        if candidate.exists() {
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            if std::fs::metadata(&candidate)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
/// No-op permission hardening on platforms without POSIX modes.
pub fn harden_permissions(_path: &Path) -> SqliteResult<()> {
    Ok(())
}

/// Migrates atomically and rejects an unknown or damaged database profile.
pub fn apply_migrations_and_verify(conn: &mut Connection) -> SqliteResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let metadata_exists: i64 = tx.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'gocode_session_binding_schema_version'",
        [],
        |row| row.get(0),
    )?;
    if metadata_exists == 0 {
        tx.execute_batch(SCHEMA_VERSION_DDL)?;
    }
    verify_authoritative_sql(
        &tx,
        "table",
        "gocode_session_binding_schema_version",
        SCHEMA_VERSION_DDL,
    )?;
    let current: i64 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM gocode_session_binding_schema_version",
        [],
        |row| row.get(0),
    )?;
    if current > CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if current < 1 {
        tx.execute_batch(MIGRATION_V1)?;
        tx.execute(
            "INSERT INTO gocode_session_binding_schema_version(version) VALUES (1)",
            [],
        )?;
    }
    tx.commit()?;
    verify_database(conn)
}
