/// Apply all schema migrations up to [`CURRENT_SCHEMA_VERSION`].
///
/// Idempotent — only runs migrations not yet applied.
pub fn apply_migrations(conn: &Connection) -> SqliteResult<()> {
    apply_migrations_internal(conn, CURRENT_SCHEMA_VERSION)
}

/// Builds the released V15 boundary for compatibility fixtures only.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn apply_migrations_through_v15_for_test(conn: &Connection) -> SqliteResult<()> {
    apply_migrations_internal(conn, 15)
}

/// Builds the released V16 boundary for V18 migration fixtures only.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn apply_migrations_through_v16_for_test(conn: &Connection) -> SqliteResult<()> {
    apply_migrations_internal(conn, 16)
}

/// Builds the locally-created V17 boundary for V18 migration fixtures only.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn apply_migrations_through_v17_for_test(conn: &Connection) -> SqliteResult<()> {
    apply_migrations_internal(conn, 17)
}

fn apply_migrations_internal(conn: &Connection, target_version: i64) -> SqliteResult<()> {
    let source_version = classify_schema_version(conn)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;
    let current_version: i64 = conn
        .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |row| row.get(0))
        .unwrap_or(0);
    apply_legacy_migrations(conn, current_version)?;
    apply_v12_and_later(conn, current_version, target_version, source_version)?;
    if current_version < target_version {
        conn.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    }
    Ok(())
}

fn classify_schema_version(conn: &Connection) -> SqliteResult<i64> {
    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !has_version_table {
        return Ok(0);
    }
    let version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |row| row.get(0),
    )?;
    let compatible = match version {
        0..=8 => true,
        9 => is_released_strict_v9(conn, version)?,
        10 => is_released_provider_v10(conn, version)?,
        11 => is_released_provider_v11(conn, version)?,
        12 => is_released_provider_v12(conn, version)?,
        13 => is_released_provider_v13(conn, version)?,
        14 => is_released_provider_v14(conn, version)?,
        15 => is_released_provider_v15(conn, version)?,
        16 => project_workspace_schema::v16_matches(conn, version)?,
        17 => replay_snapshot_schema::v17_matches(conn, version)?,
        18 => replay_promotion_snapshot_schema::v18_matches(conn, version)?,
        _ => false,
    };
    compatible.then_some(version).ok_or(rusqlite::Error::InvalidQuery)
}

fn apply_legacy_migrations(conn: &Connection, version: i64) -> SqliteResult<()> {
    if version < 1 {
        apply_sql_migration(conn, 1, MIGRATION_V1)?;
    }
    if version < 2 {
        let transaction = conn.unchecked_transaction()?;
        transaction.execute_batch(MIGRATION_V2)?;
        transaction.execute(
            "UPDATE events SET correlation_id = taskrun_id, correlation_type = 1, integrity_profile = 1",
            [],
        )?;
        transaction.execute("INSERT INTO schema_version (version) VALUES (2)", [])?;
        transaction.commit()?;
    }
    for (marker, migration) in [
        (3, MIGRATION_V3), (4, MIGRATION_V4), (5, MIGRATION_V5), (6, MIGRATION_V6),
        (7, MIGRATION_V7), (8, MIGRATION_V8), (9, MIGRATION_V9), (10, MIGRATION_V10),
        (11, MIGRATION_V11),
    ] {
        if version < marker {
            apply_sql_migration(conn, marker, migration)?;
        }
    }
    Ok(())
}

fn apply_sql_migration(conn: &Connection, marker: i64, migration: &str) -> SqliteResult<()> {
    let transaction = conn.unchecked_transaction()?;
    transaction.execute_batch(migration)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (?1)", [marker])?;
    transaction.commit()
}

fn apply_v12_and_later(
    conn: &Connection,
    source_version: i64,
    target_version: i64,
    original_version: i64,
) -> SqliteResult<()> {
    if source_version < 12 {
        apply_v12(conn)?;
    }
    if source_version < 13 {
        let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
        transaction.execute_batch(MIGRATION_V13)?;
        install_missing_v12_fence_triggers(&transaction)?;
        transaction.execute("INSERT INTO schema_version (version) VALUES (13)", [])?;
        transaction.commit()?;
    }
    if source_version < 14 {
        provider_schema::apply_v14_migration(conn, |transaction| install_missing_v12_fence_triggers(transaction))?;
    }
    if source_version < 15 {
        provider_schema::apply_v15_migration(conn)?;
    }
    if source_version < 16 && target_version >= 16 {
        project_workspace_schema::apply_v16_migration(conn)?;
    }
    if source_version < 17 && target_version == 17 {
        replay_snapshot_schema::apply_v17_migration(conn)?;
    }
    if source_version < 18 && target_version >= 18 {
        replay_promotion_snapshot_schema::apply_v18_migration(conn, original_version == 17)?;
    }
    Ok(())
}

fn apply_v12(conn: &Connection) -> SqliteResult<()> {
    if conn.path().is_some_and(|path| !path.is_empty()) {
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
    }
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
    let snapshot = create_v11_upgrade_snapshot(&transaction)?;
    transaction.execute_batch(MIGRATION_V12)?;
    transaction.execute(
        "INSERT INTO schema_upgrade_fence (id, source_version, target_version, snapshot_filename, snapshot_digest, baseline_event_next_position, baseline_provider_prepared_count, baseline_provider_attempt_count) VALUES (1, 11, 12, ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            snapshot.backup.as_ref().map(|backup| &backup.filename),
            snapshot.backup.as_ref().map(|backup| backup.digest.as_slice()),
            snapshot.baseline_event_next_position,
            snapshot.baseline_provider_prepared_count,
            snapshot.baseline_provider_attempt_count,
        ],
    )?;
    install_v12_fence_triggers(&transaction)?;
    transaction.execute("INSERT INTO schema_version (version) VALUES (12)", [])?;
    transaction.commit()
}
