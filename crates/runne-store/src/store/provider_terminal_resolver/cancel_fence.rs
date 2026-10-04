fn ensure_provider_cancel_fence(
    connection: &rusqlite::Connection,
    record: &ProviderTerminalOutboxRecord,
) -> Result<(), ProviderTerminalConversationResolveError> {
    if crate::provider::taskrun_provider_cancel_fence_matches(
        connection,
        record.taskrun_id,
        record.execution_attempt_id,
        record.attempt_id,
    )
    .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?
    {
        Ok(())
    } else {
        Err(ProviderTerminalConversationResolveError::Conflict)
    }
}

fn resolve_stream_journal_cancellation(
    tx: &rusqlite::Transaction<'_>,
    record: &ProviderTerminalOutboxRecord,
    stream: &runne_application::ports::ConversationLoadedStream,
    started: &runne_application::ports::TextGenerationReceipt,
) -> Result<
    runne_application::ports::ProviderTerminalCancellationEvidence,
    ProviderTerminalConversationResolveError,
> {
    let invalid = || ProviderTerminalConversationResolveError::Conflict;
    let conversation_terminal = stream
        .events
        .get(
            usize::try_from(
                started
                    .conversation_version
                    .checked_sub(1)
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?,
        )
        .ok_or_else(invalid)?;
    if !matches!(conversation_terminal.payload(),
        runne_domain::conversation::ConversationEvent::GenerationFailed { taskrun_id, attempt_id, reason }
            if *taskrun_id == record.taskrun_id
                && *attempt_id == record.execution_attempt_id
                && *reason == runne_domain::conversation::GenerationFailureReason::Cancelled)
    {
        return Err(invalid());
    }
    ensure_provider_cancel_fence(tx, record)?;
    let terminal_version = started.taskrun_version;
    let cancellation_version = terminal_version.checked_sub(1).ok_or_else(invalid)?;
    let cancellation_payload = taskrun_event_payload(tx, record.taskrun_id, cancellation_version)?;
    let terminal_payload = taskrun_event_payload(tx, record.taskrun_id, terminal_version)?;
    if crate::codec::TaskRunEventCodec
        .decode(&cancellation_payload)
        .map_err(|_| invalid())?
        != runne_domain::task_run::TaskRunEvent::CancellationRequested
        || crate::codec::TaskRunEventCodec
            .decode(&terminal_payload)
            .map_err(|_| invalid())?
            != runne_domain::task_run::TaskRunEvent::CancellationCompleted
    {
        return Err(invalid());
    }
    let (disposition, marker_digest): (i64, Vec<u8>) = tx
        .query_row(
            "SELECT d.disposition,p.settlement_digest
             FROM provider_terminal_dispositions d
             JOIN provider_dispatch_attempts p ON p.attempt_id=d.dispatch_attempt_id
             JOIN taskrun_terminal_settlement_receipts r ON r.taskrun_id=?1 AND r.attempt_id=?2
                AND r.terminal_version=?3 AND r.terminal_event_id=(
                    SELECT event_id FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?3)
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
                AND o.attempt_id=r.attempt_id AND o.state='released'
                AND o.release_event_id=r.terminal_event_id
             WHERE d.dispatch_attempt_id=?4 AND p.settlement_digest=?5",
            rusqlite::params![
                record.taskrun_id.as_bytes(),
                record.execution_attempt_id.as_bytes(),
                i64::try_from(terminal_version).map_err(|_| invalid())?,
                record.attempt_id.as_bytes(),
                record.settlement_digest.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| invalid())?;
    if marker_digest.as_slice() != record.settlement_digest.as_slice() || disposition != 1 {
        return Err(invalid());
    }
    Ok(
        runne_application::ports::ProviderTerminalCancellationEvidence {
            dispatch_attempt_id: *record.attempt_id.as_bytes(),
            disposition: runne_provider::ProviderTerminalDisposition::Completed,
            settlement_digest: record.settlement_digest,
            cancellation_taskrun_version: cancellation_version,
        },
    )
}

fn taskrun_event_payload(
    tx: &rusqlite::Transaction<'_>,
    taskrun: runne_domain::id::TaskRunId,
    version: u64,
) -> Result<Vec<u8>, ProviderTerminalConversationResolveError> {
    tx.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
        rusqlite::params![
            taskrun.as_bytes(),
            i64::try_from(version)
                .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?
        ],
        |row| row.get(0),
    )
    .map_err(|_| ProviderTerminalConversationResolveError::Conflict)
}
