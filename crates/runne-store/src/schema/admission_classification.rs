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
        18 => project_workspace_schema::v18_matches(conn, schema_version)?,
        19 => replay_snapshot_schema::v19_matches(conn, schema_version)?,
        20 => replay_promotion_snapshot_schema::v20_matches(conn, schema_version)?,
        21 => v21_matches(conn, schema_version)?,
        22 => v22_matches(conn, schema_version)?,
        23 => v23_matches(conn, schema_version)?,
        24 => v24_matches(conn, schema_version)?,
        25 => v25_matches(conn, schema_version)?,
        26 => v26_matches(conn, schema_version)?,
        27 => v27_matches(conn, schema_version)?,
        28 => v28_matches(conn, schema_version)?,
        29 => v29_matches(conn, schema_version)?,
        30 => v30_matches(conn, schema_version)?,
        31 => v31_matches(conn, schema_version)?,
        32 => v32_matches(conn, schema_version)?,
        33 => v33_matches(conn, schema_version)?,
        34 => v34_matches(conn, schema_version)?,
        35 => v35_matches(conn, schema_version)?,
        36 => project_workspace_schema::v36_matches(conn, schema_version)?,
        37 => v37_matches(conn, schema_version)?,
        38 => v38_matches(conn, schema_version)?,
        39 => v39_matches(conn, schema_version)?,
        40 => v40_matches(conn, schema_version)?,
        41 => v41_matches(conn, schema_version)?,
        42 => v42_matches(conn, schema_version)?,
        43 => v43_matches(conn, schema_version)?,
        44 => v44_matches(conn, schema_version)?,
        45 => v45_matches(conn, schema_version)?,
        46 => v46_matches(conn, schema_version)?,
        47 => v47_matches(conn, schema_version)?,
        48 => v48_matches(conn, schema_version)?,
        49 => v49_matches(conn, schema_version)?,
        50 => v50_matches(conn, schema_version)?,
        51 => v51_matches(conn, schema_version)?,
        52 => v52_matches(conn, schema_version)?,
        53 => v53_matches(conn, schema_version)?,
        54 => v54_matches(conn, schema_version)?,
        55 => v55_matches(conn, schema_version)?,
        56 => v56_matches(conn, schema_version)?,
        57 => v57_matches(conn, schema_version)?,
        58 => v58_matches(conn, schema_version)?,
        59 => v59_matches(conn, schema_version)?,
        60 => v60_matches(conn, schema_version)?,
        61 => v61_matches(conn, schema_version)?,
        62 => v62_matches(conn, schema_version)?,
        63 => v63_matches(conn, schema_version)?,
        64 => v64_matches(conn, schema_version)?,
        65 => v65_matches(conn, schema_version)?,
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
