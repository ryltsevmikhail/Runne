use super::support::InnerContext;

fn database(context: &InnerContext) -> Result<rusqlite::Connection, &'static str> {
    rusqlite::Connection::open_with_flags(
        context.runtime_root().join("runne-daemon/event-log.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| "revocation-sqlite-open")
}

pub(super) fn assert_partial(
    context: &InnerContext,
    cleanup: &[u8; 16],
) -> Result<(), &'static str> {
    let connection = database(context)?;
    let state: String = connection
        .query_row(
            "SELECT state FROM provider_credential_operations WHERE operation_id=?1",
            [cleanup.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| "revocation-partial-state")?;
    let receipts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_completion_receipts",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "revocation-partial-receipts")?;
    (state == "CLAIMED" && receipts == 3)
        .then_some(())
        .ok_or("revocation-partial-invariant")
}

pub(super) fn assert_terminal(context: &InnerContext) -> Result<(), &'static str> {
    let connection = database(context)?;
    let counts: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM provider_credential_operations WHERE action='PAIR' AND state='COMPLETED'),
                (SELECT COUNT(*) FROM provider_credential_operations WHERE action='REVOKE' AND state='COMPLETED'),
                (SELECT COUNT(*) FROM provider_credential_operations WHERE action='RETIRED_VERSION_CLEANUP' AND state='COMPLETED'),
                (SELECT COUNT(*) FROM provider_credential_completion_receipts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| "revocation-terminal-counts")?;
    let active: Option<i64> = connection
        .query_row(
            "SELECT active_credential_version FROM provider_credential_authority_heads WHERE provider_id='openai'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "revocation-terminal-head")?;
    let deleted: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_credential_versions WHERE provider_id='openai' AND lifecycle_state='DELETED'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "revocation-terminal-versions")?;
    (counts == (2, 1, 1, 4) && active.is_none() && deleted == 2)
        .then_some(())
        .ok_or("revocation-terminal-invariant")
}
