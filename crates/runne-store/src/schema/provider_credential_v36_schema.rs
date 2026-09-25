pub(super) fn credential_v36_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    let trigger = credential_v36_source("CREATE TRIGGER provider_credential_revoke_irreversible");
    if version != 36 {
        return Ok(false);
    }
    v24_trigger_matches(connection, "provider_credential_revoke_irreversible", trigger)
}

fn credential_v36_source(start: &str) -> &'static str {
    let start = MIGRATION_CREDENTIAL_V36
        .find(start)
        .expect("credential V36 object exists");
    let source = &MIGRATION_CREDENTIAL_V36[start..];
    let end = source.find("END;").expect("V36 trigger ends") + 4;
    &source[..end]
}
