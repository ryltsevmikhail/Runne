use super::super::*;
use runne_application::commands::CommandOutcome;

pub(super) fn verify(
    connection: &Connection,
    event: &runne_domain::event::EventEnvelope<TaskRunEvent>,
    taskrun_id: runne_domain::id::TaskRunId,
    runtime_authority_id: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let fail = || storage_failure(StorageFailureKind::IntegrityViolation);
    if event.payload() != &TaskRunEvent::CancellationRequested {
        return Err(fail());
    }
    let (scope_bytes, key, fingerprint, outcome): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [event.command_id().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| fail())?;
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| fail())?;
    let version = event.sequence();
    let expected_fingerprint =
        CommandFingerprint::for_cancel(&taskrun_id, version.checked_sub(1).ok_or_else(fail)?);
    let outcome = CommandOutcomeCodec.decode(&outcome).map_err(|_| fail())?;
    if key != event.idempotency_key().as_str().as_bytes()
        || scope.operation != OperationTag::CancelTaskRun
        || scope.runtime_authority_id != *runtime_authority_id
        || scope.aggregate_scope != (AggregateScope::ExistingTaskRun { taskrun_id })
        || fingerprint != expected_fingerprint.as_bytes()
        || outcome
            != (CommandOutcome::TaskRunCancellationRequested {
                taskrun_id,
                new_version: version,
            })
    {
        return Err(fail());
    }
    Ok(())
}
