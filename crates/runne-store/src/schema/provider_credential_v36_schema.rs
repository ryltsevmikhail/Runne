pub(super) fn v36_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    let trigger = v36_source("CREATE TRIGGER provider_credential_revoke_irreversible");
    if version != 36
        || !v35_catalog_matches(
            connection,
            &[("provider_credential_revoke_irreversible", trigger)],
        )?
    {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version), 0), COALESCE(MIN(version), 0), COUNT(*), COALESCE(SUM(version), 0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(matches!(marker, (36, 1, 35, 647) | (36, 1, 36, 666)))
}

fn v36_source(start: &str) -> &'static str {
    let start = MIGRATION_V36.find(start).expect("V36 object exists");
    let source = &MIGRATION_V36[start..];
    let end = source.find("END;").expect("V36 trigger ends") + 4;
    &source[..end]
}
