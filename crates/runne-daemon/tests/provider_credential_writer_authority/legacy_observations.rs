use super::support::InnerContext;

pub(super) fn import(context: &InnerContext) -> Result<String, &'static str> {
    operation(context, "MIGRATE_LEGACY", "COMPLETED")
}

pub(super) fn cutover(context: &InnerContext) -> Result<String, &'static str> {
    let (consumed, revision, cleanup): (i64, i64, Vec<u8>) = database(context)?
        .query_row(
            "SELECT legacy_import_consumed, legacy_consumed_lifecycle_revision, legacy_cleanup_operation_id
             FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "sqlite-cutover-observation")?;
    (consumed == 1 && revision == 2 && cleanup.len() == 16)
        .then(|| format!("cutover:{consumed}:{revision}:{}", hex::encode(cleanup)))
        .ok_or("cutover-observation")
}

pub(super) fn operation(
    context: &InnerContext,
    action: &str,
    state: &str,
) -> Result<String, &'static str> {
    let operation: Vec<u8> = database(context)?
        .query_row(
            "SELECT operation_id FROM provider_credential_operations WHERE action=?1 AND state=?2",
            [action, state],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-operation-observation")?;
    (operation.len() == 16)
        .then(|| format!("{action}:{state}:{}", hex::encode(operation)))
        .ok_or("operation-observation")
}

pub(super) fn database(context: &InnerContext) -> Result<rusqlite::Connection, &'static str> {
    rusqlite::Connection::open_with_flags(
        context.runtime_root().join("runne-daemon/event-log.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "sqlite-open")
}
