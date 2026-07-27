//! Database schema — DDL, migrations, and startup PRAGMA gates.
//!
//! The schema consists of:
//! - `schema_version` — tracks applied migrations
//! - `event_log_state` — singleton row for global position counter
//! - `aggregate_streams` — per-aggregate stream metadata
//! - `events` — committed event rows
//! - `command_receipts` — idempotency receipt store

use rusqlite::{Connection, Result as SqliteResult};

/// Current schema version. Increment when adding new DDL migrations.
pub const CURRENT_SCHEMA_VERSION: i64 = 3;

/// Apply all schema migrations up to [`CURRENT_SCHEMA_VERSION`].
///
/// Idempotent — only runs migrations not yet applied.
pub fn apply_migrations(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 1 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V1)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (1)", [])?;
        tx.commit()?;
    }

    if current_version < 2 {
        // Keep DDL, V1 backfill, and the version marker in one transaction.
        // `Transaction` rolls back on drop if any ALTER or rename fails.
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V2)?;
        tx.execute(
            "UPDATE events
             SET correlation_id = taskrun_id,
                 correlation_type = 1,
                 integrity_profile = 1",
            [],
        )?;
        tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;
        tx.commit()?;
    }

    if current_version < 3 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V3)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (3)", [])?;
        tx.commit()?;
    }

    Ok(())
}

/// Run startup gates: integrity check, FK check, and PRAGMA profile
/// verification.
///
/// Fails closed (returns an error) if any check fails.
pub fn run_startup_gates(conn: &Connection, _db_path: &str) -> SqliteResult<()> {
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut foreign_key_check = conn.prepare("PRAGMA foreign_key_check")?;
    if foreign_key_check.exists([])? {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    // PRAGMA profile verification
    verify_pragma(conn, "journal_mode", "wal")?;
    verify_pragma(conn, "synchronous", "2")?; // FULL = 2
    verify_pragma(conn, "foreign_keys", "1")?;
    #[cfg(target_os = "macos")]
    verify_pragma(conn, "fullfsync", "1")?;

    // Set file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in &["", "-wal", "-shm"] {
            let path = format!("{}{}", _db_path, suffix);
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            }
        }
    }

    Ok(())
}

/// Verify a PRAGMA value matches the expected value.
fn verify_pragma(conn: &Connection, pragma: &str, expected: &str) -> SqliteResult<()> {
    let sql = format!("PRAGMA {};", pragma);
    // PRAGMAs return either text or integer — try integer first, then text
    let actual: String = conn.query_row(&sql, [], |row| {
        row.get::<_, String>(0).or_else(|_| {
            let val: i32 = row.get(0)?;
            Ok(val.to_string())
        })
    })?;
    if actual != expected {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
            Some(format!(
                "PRAGMA {} = '{}', expected '{}'",
                pragma, actual, expected
            )),
        ));
    }
    Ok(())
}

// ── Migration V1: initial schema ─────────────────────────────────────────

const MIGRATION_V1: &str = r#"
CREATE TABLE event_log_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_global_position INTEGER NOT NULL DEFAULT 1
);

INSERT INTO event_log_state (singleton, next_global_position) VALUES (1, 1);

CREATE TABLE task_run_streams (
    taskrun_id BLOB PRIMARY KEY,
    current_version INTEGER NOT NULL DEFAULT 0,
    last_event_id BLOB,
    last_timestamp INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE events (
    event_id BLOB PRIMARY KEY,
    taskrun_id BLOB NOT NULL REFERENCES task_run_streams(taskrun_id),
    sequence INTEGER NOT NULL,
    global_position INTEGER NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL,
    aggregate_type INTEGER NOT NULL,
    sensitivity INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    causation_id BLOB,
    command_id BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    actor BLOB NOT NULL,
    payload BLOB NOT NULL,
    integrity_digest BLOB NOT NULL,
    UNIQUE(taskrun_id, sequence)
);

CREATE INDEX idx_events_taskrun_sequence
    ON events(taskrun_id, sequence);

CREATE TABLE command_receipts (
    command_id BLOB NOT NULL,
    idempotency_scope_bytes BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    command_outcome BLOB NOT NULL,
    committed_at INTEGER NOT NULL,
    UNIQUE(command_id),
    UNIQUE(idempotency_scope_bytes, idempotency_key)
);

CREATE INDEX idx_receipts_scope_key
    ON command_receipts(idempotency_scope_bytes, idempotency_key);
"#;

// ── Migration V2: correlation_id + aggregate_streams ─────────────────────

const MIGRATION_V2: &str = r#"
ALTER TABLE events ADD COLUMN correlation_id BLOB NOT NULL DEFAULT x'';
ALTER TABLE events ADD COLUMN correlation_type INTEGER NOT NULL DEFAULT 1;
ALTER TABLE events ADD COLUMN integrity_profile INTEGER NOT NULL DEFAULT 1;

ALTER TABLE task_run_streams RENAME TO aggregate_streams;
"#;

// ── Migration V3: typed aggregate stream identity ───────────────────────

const MIGRATION_V3: &str = r#"
CREATE TABLE aggregate_streams_v3 (
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    current_version INTEGER NOT NULL DEFAULT 0 CHECK(current_version >= 0),
    last_event_id BLOB CHECK(last_event_id IS NULL OR length(last_event_id) = 16),
    last_timestamp INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(aggregate_type, aggregate_id)
);

INSERT INTO aggregate_streams_v3
    (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
SELECT 1, taskrun_id, current_version, last_event_id, last_timestamp, created_at
FROM aggregate_streams;

CREATE TABLE events_v3 (
    event_id BLOB PRIMARY KEY CHECK(length(event_id) = 16),
    aggregate_type INTEGER NOT NULL CHECK(aggregate_type IN (1, 2)),
    aggregate_id BLOB NOT NULL CHECK(length(aggregate_id) = 16),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    global_position INTEGER NOT NULL UNIQUE CHECK(global_position > 0),
    timestamp INTEGER NOT NULL,
    sensitivity INTEGER NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version BETWEEN 0 AND 4294967295),
    causation_id BLOB CHECK(causation_id IS NULL OR length(causation_id) = 16),
    command_id BLOB NOT NULL CHECK(length(command_id) = 16),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    actor BLOB NOT NULL CHECK(length(actor) BETWEEN 1 AND 256),
    payload BLOB NOT NULL,
    integrity_digest BLOB NOT NULL CHECK(length(integrity_digest) = 32),
    correlation_id BLOB NOT NULL CHECK(length(correlation_id) = 16),
    correlation_type INTEGER NOT NULL CHECK(correlation_type IN (1, 2)),
    integrity_profile INTEGER NOT NULL CHECK(integrity_profile IN (1, 2)),
    FOREIGN KEY(aggregate_type, aggregate_id)
        REFERENCES aggregate_streams_v3(aggregate_type, aggregate_id),
    UNIQUE(aggregate_type, aggregate_id, sequence)
);

INSERT INTO events_v3
    (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
     sensitivity, schema_version, causation_id, command_id, idempotency_key,
     actor, payload, integrity_digest, correlation_id, correlation_type,
     integrity_profile)
SELECT event_id, aggregate_type, taskrun_id, sequence, global_position, timestamp,
       sensitivity, schema_version, causation_id, command_id, idempotency_key,
       actor, payload, integrity_digest, correlation_id, correlation_type,
       integrity_profile
FROM events;

DROP TABLE events;
DROP TABLE aggregate_streams;
ALTER TABLE aggregate_streams_v3 RENAME TO aggregate_streams;
ALTER TABLE events_v3 RENAME TO events;

CREATE INDEX idx_events_aggregate_sequence
    ON events(aggregate_type, aggregate_id, sequence);
"#;

/// Open a database connection with the standard set of PRAGMAs.
pub fn open_with_pragmas(db_path: &str) -> SqliteResult<Connection> {
    let conn = Connection::open(db_path)?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;

    // macOS-specific: fullfsync
    #[cfg(target_os = "macos")]
    {
        conn.execute_batch("PRAGMA fullfsync = ON;")?;
    }

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    const TEST_ID: [u8; 16] = [0x42; 16];

    fn initialize_v1(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    #[test]
    fn migrations_backfill_v1_event_without_changing_durable_identity() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_v1(&conn);
        conn.execute(
            "INSERT INTO task_run_streams
             (taskrun_id, current_version, last_event_id, last_timestamp, created_at)
             VALUES (?1, 1, ?1, 0, 0)",
            params![TEST_ID],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events
             (event_id, taskrun_id, sequence, global_position, timestamp,
              aggregate_type, sensitivity, schema_version, causation_id,
              command_id, idempotency_key, actor, payload, integrity_digest)
             VALUES (?1, ?1, 1, 1, 0, 1, 0, 1, NULL, ?1, x'01', x'02', x'03', zeroblob(32))",
            params![TEST_ID],
        )
        .unwrap();

        apply_migrations(&conn).unwrap();

        let (
            aggregate_id,
            correlation_id,
            correlation_type,
            integrity_profile,
            global_position,
            integrity_digest,
        ): (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>) = conn
            .query_row(
                "SELECT aggregate_id, correlation_id, correlation_type, integrity_profile,
                        global_position, integrity_digest
                 FROM events",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(aggregate_id, TEST_ID);
        assert_eq!(correlation_id, TEST_ID);
        assert_eq!(correlation_type, 1);
        assert_eq!(integrity_profile, 1);
        assert_eq!(global_position, 1);
        assert_eq!(integrity_digest, vec![0; 32]);

        let stream_type: i64 = conn
            .query_row(
                "SELECT aggregate_type FROM aggregate_streams WHERE aggregate_id = ?1",
                params![TEST_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stream_type, 1);
    }

    #[test]
    fn test_failed_v2_migration_rolls_back_and_can_retry() {
        let conn = Connection::open_in_memory().unwrap();
        initialize_v1(&conn);
        conn.execute_batch("CREATE TABLE aggregate_streams (taskrun_id BLOB PRIMARY KEY)")
            .unwrap();

        assert!(apply_migrations(&conn).is_err());

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 1);
        let correlation_column_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'correlation_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(correlation_column_count, 0);

        conn.execute_batch("DROP TABLE aggregate_streams").unwrap();
        apply_migrations(&conn).unwrap();

        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'aggregate_streams'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }
}
