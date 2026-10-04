use super::super::*;
use runne_application::commands::CommandOutcome;

pub(super) fn verify(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let fail = || storage_failure(StorageFailureKind::IntegrityViolation);
    let cancellation_version = payload
        .expected_started_taskrun_version
        .checked_add(1)
        .ok_or_else(fail)?;
    let (command_bytes, event_key): (Vec<u8>, Vec<u8>) = tx
        .query_row(
            "SELECT command_id,idempotency_key FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
            params![
                payload.receipt.taskrun_id.as_bytes(),
                i64::try_from(cancellation_version).map_err(|_| fail())?
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| fail())?;
    let event_payload: Vec<u8> = tx
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
            params![
                payload.receipt.taskrun_id.as_bytes(),
                i64::try_from(cancellation_version).map_err(|_| fail())?
            ],
            |row| row.get(0),
        )
        .map_err(|_| fail())?;
    if TaskRunEventCodec
        .decode(&event_payload)
        .map_err(|_| fail())?
        != TaskRunEvent::CancellationRequested
    {
        return Err(fail());
    }
    let command_id =
        CommandId::from_bytes(command_bytes.as_slice().try_into().map_err(|_| fail())?);
    let (scope_bytes, stored_key, fingerprint, outcome): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = tx
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| fail())?;
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| fail())?;
    let expected_fingerprint = CommandFingerprint::for_cancel(
        &payload.receipt.taskrun_id,
        payload.expected_started_taskrun_version,
    );
    let outcome = CommandOutcomeCodec.decode(&outcome).map_err(|_| fail())?;
    if event_key != stored_key
        || scope.operation != OperationTag::CancelTaskRun
        || scope.runtime_authority_id != *authority
        || scope.aggregate_scope
            != (AggregateScope::ExistingTaskRun {
                taskrun_id: payload.receipt.taskrun_id,
            })
        || fingerprint != expected_fingerprint.as_bytes()
        || outcome
            != (CommandOutcome::TaskRunCancellationRequested {
                taskrun_id: payload.receipt.taskrun_id,
                new_version: cancellation_version,
            })
    {
        return Err(fail());
    }
    Ok(())
}
