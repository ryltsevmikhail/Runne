include!("migration_control/apply.rs");
include!("migration_control/classification.rs");
include!("migration_control/execution.rs");

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
