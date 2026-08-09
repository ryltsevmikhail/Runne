/// Apply all schema migrations up to [`CURRENT_SCHEMA_VERSION`].
///
/// Idempotent — only runs migrations not yet applied.
pub fn apply_migrations(conn: &Connection) -> SqliteResult<()> {
    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if has_version_table {
        let existing_version: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;
        let compatible = match existing_version {
            0..=8 => true,
            9 => is_released_strict_v9(conn, existing_version)?,
            10 => is_released_provider_v10(conn, existing_version)?,
            11 => is_released_provider_v11(conn, existing_version)?,
            12 => is_released_provider_v12(conn, existing_version)?,
            13 => is_released_provider_v13(conn, existing_version)?,
            14 => is_released_provider_v14(conn, existing_version)?,
            15 => is_released_provider_v15(conn, existing_version)?,
            16 => is_released_provider_v16(conn, existing_version)?,
            _ => false,
        };
        if !compatible {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
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

    if current_version < 4 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V4)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (4)", [])?;
        tx.commit()?;
    }

    if current_version < 5 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V5)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (5)", [])?;
        tx.commit()?;
    }

    if current_version < 6 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V6)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (6)", [])?;
        tx.commit()?;
    }

    if current_version < 7 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V7)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (7)", [])?;
        tx.commit()?;
    }

    if current_version < 8 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V8)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (8)", [])?;
        tx.commit()?;
    }

    if current_version < 9 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V9)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (9)", [])?;
        tx.commit()?;
    }

    if current_version < 10 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V10)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (10)", [])?;
        tx.commit()?;
    }

    if current_version < 11 {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(MIGRATION_V11)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (11)", [])?;
        tx.commit()?;
    }

    if current_version < 12 {
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
        let snapshot = create_v11_upgrade_snapshot(&tx)?;
        tx.execute_batch(MIGRATION_V12)?;
        tx.execute(
            "INSERT INTO schema_upgrade_fence (
                id, source_version, target_version, snapshot_filename, snapshot_digest,
                baseline_event_next_position, baseline_provider_prepared_count,
                baseline_provider_attempt_count
             ) VALUES (1, 11, 12, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                snapshot.backup.as_ref().map(|backup| &backup.filename),
                snapshot
                    .backup
                    .as_ref()
                    .map(|backup| backup.digest.as_slice()),
                snapshot.baseline_event_next_position,
                snapshot.baseline_provider_prepared_count,
                snapshot.baseline_provider_attempt_count,
            ],
        )?;
        install_v12_fence_triggers(&tx)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (12)", [])?;
        tx.commit()?;
    }

    if current_version < 13 {
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
        tx.execute_batch(MIGRATION_V13)?;
        install_missing_v12_fence_triggers(&tx)?;
        tx.execute("INSERT INTO schema_version (version) VALUES (13)", [])?;
        tx.commit()?;
    }

    if current_version < 14 {
        provider_schema::apply_v14_migration(conn, |tx| install_missing_v12_fence_triggers(tx))?;
    }

    if current_version < 15 {
        provider_schema::apply_v15_migration(conn)?;
    }

    if current_version < 16 {
        apply_v16_migration(conn)?;
    }

    if current_version < CURRENT_SCHEMA_VERSION {
        // Preflight classifies the immutable main database without consulting
        // a hot WAL. Publish completed schema migrations before another
        // process or connection attempts admission.
        conn.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    }

    Ok(())
}

fn is_released_strict_v9(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 9 {
        return Ok(false);
    }
    is_released_strict_v9_contents(conn, false)
}

fn is_released_strict_v9_with_v12_fence(conn: &Connection) -> SqliteResult<bool> {
    is_released_strict_v9_contents(conn, true)
}

fn is_released_strict_v9_contents(
    conn: &Connection,
    allows_v12_fence_triggers: bool,
) -> SqliteResult<bool> {
    if !table_shape_matches(
        conn,
        "verification_evidence",
        &VERIFICATION_EVIDENCE_COLUMNS,
    )? || !table_shape_matches(conn, "consumption_intents", &CONSUMPTION_INTENT_COLUMNS)?
        || !table_shape_matches(conn, "schema_lineage", &SCHEMA_LINEAGE_COLUMNS)?
        || !table_sql_matches(
            conn,
            "verification_evidence",
            CANONICAL_VERIFICATION_EVIDENCE_SQL,
        )?
        || !table_sql_matches(
            conn,
            "consumption_intents",
            CANONICAL_CONSUMPTION_INTENTS_SQL,
        )?
        || !table_sql_matches(conn, "schema_lineage", CANONICAL_SCHEMA_LINEAGE_SQL)?
        || !index_matches(
            conn,
            "idx_evidence_run",
            "verification_evidence",
            &["run_id"],
        )?
    {
        return Ok(false);
    }

    let marker_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM schema_lineage", [], |row| row.get(0))?;
    let marker_matches: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_lineage WHERE schema_version = 9 AND provenance = 'released-v8-to-strict-v9')",
        [],
        |row| row.get(0),
    )?;
    if marker_count != 1
        || !marker_matches
        || has_candidate_remnant(conn, allows_v12_fence_triggers)?
    {
        return Ok(false);
    }
    Ok(true)
}

fn is_released_provider_v10(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 10 || !is_released_strict_v9(conn, 9)? {
        return Ok(false);
    }
    Ok(table_shape_matches(
        conn,
        "provider_prepared_requests",
        &PROVIDER_PREPARED_COLUMNS,
    )? && table_sql_matches_migration(conn, "provider_prepared_requests", MIGRATION_V10)?
        && table_shape_matches(
            conn,
            "provider_dispatch_attempts",
            &PROVIDER_DISPATCH_COLUMNS,
        )?
        && table_sql_matches_migration(conn, "provider_dispatch_attempts", MIGRATION_V10)?)
}

fn is_released_provider_v11(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 11 || !is_released_provider_v10(conn, 10)? {
        return Ok(false);
    }
    Ok(table_shape_matches(
        conn,
        "provider_effect_authorities",
        &PROVIDER_EFFECT_AUTHORITY_COLUMNS,
    )? && table_sql_matches_migration(conn, "provider_effect_authorities", MIGRATION_V11)?)
}
