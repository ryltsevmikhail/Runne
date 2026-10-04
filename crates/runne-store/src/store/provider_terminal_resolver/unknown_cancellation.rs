use super::*;

pub(super) fn resolve(
    tx: &rusqlite::Transaction<'_>,
    record: &ProviderTerminalOutboxRecord,
    commitment: [u8; 32],
    cancellation_taskrun_version: u64,
) -> Result<
    runne_runtime::provider_execution::RecoveredProviderTerminalCancellation,
    ProviderTerminalConversationResolveError,
> {
    let exact: bool = tx
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_unknown_terminal_receipts r
                JOIN provider_dispatch_attempts d ON d.attempt_id=r.dispatch_attempt_id
                WHERE r.dispatch_attempt_id=?1 AND r.unknown_commitment=?2
                  AND r.terminal_disposition=1 AND r.outbox_id=?3
                  AND r.application_idempotency_key=?4
                  AND d.state=4 AND d.settlement_digest=?2
                  AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements s
                    WHERE s.dispatch_attempt_id=d.attempt_id)
                  AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions m
                    WHERE m.dispatch_attempt_id=d.attempt_id))",
            params![
                record.attempt_id.as_bytes(),
                commitment.as_slice(),
                record.outbox_id.as_slice(),
                record.application_idempotency_key
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
    if !exact {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    Ok(
        runne_runtime::provider_execution::RecoveredProviderTerminalCancellation::UnknownJournal(
            runne_application::ports::ProviderUnknownTerminalCancellationEvidence {
                dispatch_attempt_id: *record.attempt_id.as_bytes(),
                disposition: runne_provider::ProviderTerminalDisposition::Completed,
                unknown_commitment: commitment,
                cancellation_taskrun_version,
            },
        ),
    )
}
