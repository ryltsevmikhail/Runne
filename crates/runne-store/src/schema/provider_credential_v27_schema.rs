const V27_TRIGGERS: [&str; 3] = ["provider_credential_migration_provenance_insert", "provider_credential_migration_provenance_immutable", "provider_credential_claimed_attempt_transition"];

pub(super) fn v27_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 27
        || !v26_predecessor_matches_with(connection, v27_operation_table_matches, v27_trigger_catalog_matches, false)?
        || !v26_catalog_matches(connection)?
    {
        return Ok(false);
    }
    for table in [V26_ISSUANCE_EVIDENCE_TABLE, V26_CLAIM_PROVIDER_TABLE, V26_TABLE] {
        let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", [table], |row| row.get(0)).optional()?;
        if actual.is_none_or(|sql| normalize_v24_ddl(&sql) != v26_table_source(table)) { return Ok(false); }
    }
    for name in V26_TRIGGERS { if !v24_trigger_matches(connection, name, v26_trigger_source(name))? { return Ok(false); } }
    for name in V27_TRIGGERS { if !v24_trigger_matches(connection, name, v27_trigger_source(name))? { return Ok(false); } }
    v27_marker_matches(connection)
}

fn v27_operation_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_credential_operations'", [], |row| row.get(0)).optional()?;
    Ok(actual.is_some_and(|sql| normalize_v24_ddl(&sql) == v27_operation_table_source()))
}

fn v27_operation_table_source() -> String {
    v25_operation_table_source().replacen(
        ",check((allocated_credential_version",
        ",broker_migration_binding_digestblobcheck(broker_migration_binding_digestisnullorlength(broker_migration_binding_digest)=32),claimed_ticket_attemptintegercheck(claimed_ticket_attemptisnullorclaimed_ticket_attempt>0),check((allocated_credential_version",
        1,
    )
}

fn v27_marker_matches(connection: &Connection) -> SqliteResult<bool> {
    let marker: (i64, i64, i64, i64) = connection.query_row("SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?;
    Ok(matches!(marker, (27, 1, 26, 359) | (27, 1, 27, 378)))
}

fn v27_trigger_source(name: &str) -> &'static str {
    let start = MIGRATION_V27.find(&format!("CREATE TRIGGER {name}")).expect("V27 trigger exists");
    let end = MIGRATION_V27[start..].find("END;").expect("V27 trigger ends") + start + 3;
    &MIGRATION_V27[start..end]
}

fn v27_trigger_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    let additional = V27_TRIGGERS.map(|name| (name, v27_trigger_source(name)));
    v26_trigger_catalog::matches_with_additional(connection, &additional)
}
