const V25_REPLACED_TRIGGERS: [&str; 3] = [
    "provider_credential_operation_insert_prepared",
    "provider_credential_operation_transition",
    "provider_credential_ticket_insert_issued",
];

pub(super) fn install_v25_successor_triggers(transaction: &Transaction<'_>) -> SqliteResult<()> {
    for (name, source) in V24_TRIGGERS {
        if V25_REPLACED_TRIGGERS.contains(&name) {
            transaction.execute_batch(&v25_trigger(name, source))?;
        }
    }
    Ok(())
}

pub(super) fn v25_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 25
        || !v24_predecessor_matches(connection)?
        || !v24_catalog_matches(connection)?
        || !v25_marker_matches(connection)?
        || !v25_operation_table_matches(connection)?
        || !v24_index_matches(connection, "provider_credential_one_non_terminal_operation")?
    {
        return Ok(false);
    }
    for table in [
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
    ] {
        if !v24_table_sql_matches_migration(connection, table)? {
            return Ok(false);
        }
    }
    for (name, source) in V24_TRIGGERS {
        let expected = if V25_REPLACED_TRIGGERS.contains(&name) {
            v25_trigger(name, source)
        } else {
            source.to_owned()
        };
        if !v24_trigger_matches(connection, name, &expected)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn v25_marker_matches(connection: &Connection) -> SqliteResult<bool> {
    let tuple: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(tuple == (25, 1, 25, 325))
}

fn v25_operation_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_credential_operations'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(sql.is_some_and(|actual| normalize_v24_ddl(&actual) == v25_operation_table_source()))
}

fn v25_operation_table_source() -> String {
    let v24 = MIGRATION_V24
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with("CREATE TABLE provider_credential_operations "))
        .expect("V24 operation table is frozen");
    normalize_v24_ddl(v24).replacen(
        "),check((allocated_credential_version",
        "),begin_proof_expires_at_high_waterintegernotnulldefault0check(begin_proof_expires_at_high_water>=0),check((allocated_credential_version",
        1,
    )
}

fn v25_trigger(name: &str, source: &str) -> String {
    match name {
        "provider_credential_operation_insert_prepared" => source.replace(
            "WHEN NEW.state != 'PREPARED'",
            "WHEN NEW.begin_proof_expires_at_high_water <= 0 OR NEW.state != 'PREPARED'",
        ),
        "provider_credential_operation_transition" => source.replace(
            "OR NEW.begin_proof_digest != OLD.begin_proof_digest",
            "OR NEW.begin_proof_digest != OLD.begin_proof_digest OR NEW.begin_proof_expires_at_high_water != OLD.begin_proof_expires_at_high_water",
        ),
        "provider_credential_ticket_insert_issued" => source
            .replace(
                " OR EXISTS(SELECT 1 FROM provider_credential_ticket_attempts",
                " OR EXISTS(SELECT 1 FROM provider_credential_operations AS o WHERE o.operation_id = NEW.operation_id AND (o.begin_proof_expires_at_high_water = 0 OR NEW.issued_at >= o.begin_proof_expires_at_high_water)) OR EXISTS(SELECT 1 FROM provider_credential_ticket_attempts",
            )
            .replace(
                "BEGIN SELECT RAISE(ABORT, 'credential ticket must begin at the strict next attempt after prior tombstones'); END",
                "BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM provider_credential_operations AS o WHERE o.operation_id = NEW.operation_id AND (o.begin_proof_expires_at_high_water = 0 OR NEW.issued_at >= o.begin_proof_expires_at_high_water)) THEN RAISE(ABORT, 'credential ticket begin proof expiry is stale') ELSE RAISE(ABORT, 'credential ticket must begin at the strict next attempt after prior tombstones') END; END",
            ),
        _ => unreachable!("only V25 successor triggers are transformed"),
    }
}
