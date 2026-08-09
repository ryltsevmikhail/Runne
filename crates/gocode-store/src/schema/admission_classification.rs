/// Classify an existing database before any pragma or statement that can
/// mutate the main database or its sidecars.
fn classify_existing_connection(conn: &Connection) -> SqliteResult<()> {
    let user_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if user_version > CURRENT_SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    let has_version_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !has_version_table {
        return Err(rusqlite::Error::InvalidQuery);
    }

    let schema_version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if schema_version == 8 && is_released_v8(conn)? {
        return Ok(());
    }
    let compatible = match schema_version {
        9 => is_released_strict_v9(conn, schema_version)?,
        10 => is_released_provider_v10(conn, schema_version)?,
        11 => is_released_provider_v11(conn, schema_version)?,
        12 => is_released_provider_v12(conn, schema_version)?,
        13 => is_released_provider_v13(conn, schema_version)?,
        14 => is_released_provider_v14(conn, schema_version)?,
        15 => is_released_provider_v15(conn, schema_version)?,
        16 => is_released_provider_v16(conn, schema_version)?,
        17 => is_released_provider_v17(conn, schema_version)?,
        _ => false,
    };
    if compatible {
        return Ok(());
    }
    Err(rusqlite::Error::InvalidQuery)
}

fn is_released_v8(conn: &Connection) -> SqliteResult<bool> {
    let version_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))?;
    let min_version: i64 = conn.query_row(
        "SELECT COALESCE(MIN(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    if version_count != 8 || min_version != 1 {
        return Ok(false);
    }

    const RELEASED_V8_TABLES: &[&str] = &[
        "event_log_state",
        "aggregate_streams",
        "events",
        "command_receipts",
        "migration_plans",
        "migration_transitions",
        "migration_evidence",
        "routing_snapshots",
        "routing_head",
        "runtime_bindings",
        "migration_reports",
        "cutover_manifests",
        "rollback_manifests",
        "retirement_manifests",
        "migration_receipts",
        "migration_audit",
        "routing_dispatch_intents",
        "security_dispatch_intents",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_audit_pre_effect",
        "security_permit_claims",
        "_authority",
        "_daemon_info",
        "_replay_subscriptions",
    ];
    RELEASED_V8_TABLES.iter().try_fold(true, |matches, table| {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        Ok(matches && exists)
    })
}
