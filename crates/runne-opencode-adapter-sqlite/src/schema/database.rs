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
        "SELECT COALESCE(MAX(version), 0) FROM runne_session_binding_schema_version",
        [],
        |row| row.get(0),
    )?;
    if current != CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    verify_authoritative_sql(
        conn,
        "table",
        "runne_session_binding_schema_version",
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
        "runne_session_binding_state",
        "",
        "CREATE TABLE runne_session_binding_state",
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
        "SELECT COUNT(*) FROM runne_session_binding_state",
        [],
        |row| row.get(0),
    )?;
    if state_count != 1 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let (singleton, last_created_at): (i64, i64) = conn.query_row(
        "SELECT singleton, last_created_at FROM runne_session_binding_state",
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
