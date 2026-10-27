/// Run startup gates: integrity check, FK check, and PRAGMA profile
/// verification.
///
/// Fails closed (returns an error) if any check fails.
pub(crate) fn run_startup_gates_raw(conn: &Connection, _db_path: &str) -> SqliteResult<()> {
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
    if schema_version >= 17 {
        crate::store::snapshot::validate_all_replay_snapshots(conn)?;
    }
    validate_no_admission_cancellation_receipts(conn)?;

    // PRAGMA profile verification
    verify_pragma(conn, "journal_mode", "wal")?;
    verify_pragma(conn, "synchronous", "2")?; // FULL = 2
    verify_pragma(conn, "foreign_keys", "1")?;
    #[cfg(target_os = "macos")]
    verify_pragma(conn, "fullfsync", "1")?;

    // Factory open/admission owns file policy. Integrity/readiness inspection
    // must not chmod caller-selected paths (including CWD-relative sidecars).

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
        return Err(profile_mismatch(pragma, &actual, expected));
    }
    Ok(())
}

// ── Migration V1: initial schema ─────────────────────────────────────────

#[cfg(all(test, target_os = "linux"))]
#[path = "startup_permission_tests.rs"]
mod startup_permission_tests;
