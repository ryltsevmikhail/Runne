//! SQLite schema migration and connection integrity checks.

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

fn verify_database(conn: &Connection) -> SqliteResult<()> {
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut fk = conn.prepare("PRAGMA foreign_key_check")?;
    if fk.exists([])? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let current: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM gocode_session_binding_schema_version",
        [],
        |row| row.get(0),
    )?;
    if current != CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    verify_authoritative_sql(
        conn,
        "table",
        "gocode_session_binding_schema_version",
        SCHEMA_VERSION_DDL,
    )?;
    let table_sql: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='session_bindings'",
        [],
        |row| row.get(0),
    )?;
    verify_exact_sql(
        conn,
        "table",
        "session_bindings",
        &table_sql,
        "CREATE TABLE session_bindings",
    )?;
    verify_exact_sql(
        conn,
        "table",
        "gocode_session_binding_state",
        "",
        "CREATE TABLE gocode_session_binding_state",
    )?;
    verify_exact_sql(
        conn,
        "index",
        "idx_session_bindings_recovery",
        "",
        "CREATE INDEX idx_session_bindings_recovery",
    )?;
    for required in [
        "session_id TEXT NOT NULL",
        "profile_id TEXT NOT NULL",
        "command_id BLOB NOT NULL UNIQUE",
        "context_snapshot BLOB NOT NULL",
        "CHECK ((status = 'pending' AND response_snapshot IS NULL)",
    ] {
        if !table_sql.contains(required) {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    let index_sql: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_session_bindings_recovery'",
        [],
        |row| row.get(0),
    )?;
    if !index_sql.contains("runtime_authority_id, status, created_at") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut columns = conn.prepare("PRAGMA table_xinfo(session_bindings)")?;
    let actual = columns
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = [
        ("session_id", "TEXT", 1, 1),
        ("profile_id", "TEXT", 1, 2),
        ("profile_revision", "INTEGER", 1, 3),
        ("runtime_authority_id", "TEXT", 1, 4),
        ("conversation_id", "BLOB", 1, 0),
        ("workspace_id", "BLOB", 1, 0),
        ("command_id", "BLOB", 1, 0),
        ("idempotency_key", "BLOB", 1, 0),
        ("request_fingerprint", "BLOB", 1, 0),
        ("context_codec_version", "INTEGER", 1, 0),
        ("context_snapshot", "BLOB", 1, 0),
        ("response_codec_version", "INTEGER", 1, 0),
        ("response_snapshot", "BLOB", 0, 0),
        ("created_at", "INTEGER", 1, 0),
        ("status", "TEXT", 1, 0),
    ];
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.0 != expected.0
                || actual.1 != expected.1
                || actual.2 != expected.2
                || actual.3 != expected.3
        })
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let state_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM gocode_session_binding_state",
        [],
        |row| row.get(0),
    )?;
    if state_count != 1 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let (singleton, last_created_at): (i64, i64) = conn.query_row(
        "SELECT singleton, last_created_at FROM gocode_session_binding_state",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if singleton != 1 || last_created_at < 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let max_created_at: i64 = conn.query_row(
        "SELECT COALESCE(MAX(created_at), 0) FROM session_bindings",
        [],
        |row| row.get(0),
    )?;
    if last_created_at < max_created_at {
        return Err(rusqlite::Error::InvalidQuery);
    }
    verify_index_columns(
        conn,
        "idx_session_bindings_recovery",
        &[
            "runtime_authority_id",
            "status",
            "created_at",
            "session_id",
            "profile_id",
            "profile_revision",
        ],
        false,
    )?;
    let command_unique = conn
        .prepare("PRAGMA index_list(session_bindings)")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|(name, unique)| {
            unique == 1
                && conn
                    .prepare(&format!("PRAGMA index_info({name})"))
                    .and_then(|mut statement| {
                        statement
                            .query_map([], |row| row.get::<_, String>(2))?
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .is_ok_and(|columns| {
                        columns
                            .iter()
                            .map(String::as_str)
                            .eq(["command_id"].iter().copied())
                    })
        });
    if !command_unique {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn verify_exact_sql(
    conn: &Connection,
    object_type: &str,
    name: &str,
    supplied: &str,
    migration_prefix: &str,
) -> SqliteResult<()> {
    let actual = if supplied.is_empty() {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            [object_type, name],
            |row| row.get::<_, String>(0),
        )?
    } else {
        supplied.to_owned()
    };
    let expected = MIGRATION_V1
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(migration_prefix))
        .ok_or(rusqlite::Error::InvalidQuery)?;
    verify_normalized_sql(&actual, expected)
}

fn verify_authoritative_sql(
    conn: &Connection,
    object_type: &str,
    name: &str,
    expected: &str,
) -> SqliteResult<()> {
    let actual = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
        [object_type, name],
        |row| row.get::<_, String>(0),
    )?;
    verify_normalized_sql(&actual, expected)
}

fn verify_normalized_sql(actual: &str, expected: &str) -> SqliteResult<()> {
    if normalize_sql(actual) != normalize_sql(expected) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote_terminator = None;

    while let Some(character) = characters.next() {
        match quote_terminator {
            Some(terminator) => {
                normalized.push(character);
                if character == terminator {
                    if characters.peek().is_some_and(|next| *next == terminator) {
                        if let Some(escaped_terminator) = characters.next() {
                            normalized.push(escaped_terminator);
                        }
                    } else {
                        quote_terminator = None;
                    }
                }
            }
            None if matches!(character, '\'' | '"' | '`') => {
                quote_terminator = Some(character);
                normalized.push(character);
            }
            None if character == '[' => {
                quote_terminator = Some(']');
                normalized.push(character);
            }
            None if character.is_whitespace() => {}
            None => normalized.extend(character.to_lowercase()),
        }
    }

    normalized
}

fn verify_index_columns(
    conn: &Connection,
    index: &str,
    expected: &[&str],
    unique: bool,
) -> SqliteResult<()> {
    let index_exists = conn
        .prepare("PRAGMA index_list(session_bindings)")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|(name, actual_unique)| name == index && (actual_unique == 1) == unique);
    if !index_exists {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let columns = conn
        .prepare(&format!("PRAGMA index_info({index})"))?
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if columns
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn verify_pragmas(conn: &Connection) -> SqliteResult<()> {
    let journal: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let busy_timeout: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || busy_timeout != 5_000
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    #[cfg(target_os = "macos")]
    {
        let fullfsync: i64 = conn.query_row("PRAGMA fullfsync", [], |row| row.get(0))?;
        if fullfsync != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_initial_migration_does_not_advance_namespaced_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE session_bindings (unexpected INTEGER);")
            .unwrap();
        assert!(apply_migrations_and_verify(&mut conn).is_err());
        let metadata: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'gocode_session_binding_schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(metadata, 0);
    }

    #[test]
    fn exact_schema_rejects_a_reordered_recovery_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations_and_verify(&mut conn).unwrap();
        conn.execute_batch(
            "DROP INDEX idx_session_bindings_recovery;
             CREATE INDEX idx_session_bindings_recovery
             ON session_bindings(status, runtime_authority_id, created_at, session_id, profile_id, profile_revision);",
        )
        .unwrap();
        assert!(verify_database(&conn).is_err());
    }

    #[test]
    fn exact_schema_rejects_changed_quoted_check_literal() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations_and_verify(&mut conn).unwrap();
        conn.execute_batch("PRAGMA writable_schema = ON;").unwrap();
        conn.execute(
            "UPDATE sqlite_master
             SET sql = replace(sql, ?1, ?2)
             WHERE type = 'table' AND name = 'session_bindings'",
            ["'pending'", "'PENDING'"],
        )
        .unwrap();
        conn.execute_batch("PRAGMA writable_schema = OFF;").unwrap();

        assert!(verify_database(&conn).is_err());
    }

    #[test]
    fn exact_schema_rejects_damaged_namespaced_metadata_ddl() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations_and_verify(&mut conn).unwrap();
        conn.execute_batch("PRAGMA writable_schema = ON;").unwrap();
        conn.execute(
            "UPDATE sqlite_master
             SET sql = replace(sql, ?1, ?2)
             WHERE type = 'table'
               AND name = 'gocode_session_binding_schema_version'",
            ["version INTEGER PRIMARY KEY", "version INTEGER"],
        )
        .unwrap();
        conn.execute_batch("PRAGMA writable_schema = OFF;").unwrap();

        assert!(verify_database(&conn).is_err());
    }
}
