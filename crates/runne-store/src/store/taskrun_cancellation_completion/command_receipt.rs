use super::*;

type CancellationCommandReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub(super) fn duplicate(
    tx: &rusqlite::Transaction<'_>,
    request: &Request,
    scope: &[u8],
    taskrun_id: TaskRunId,
) -> Result<Option<Receipt>, Error> {
    let row: Option<CancellationCommandReceiptRow> = tx
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [request.command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?;
    let Some((stored_scope, key, fingerprint, outcome)) = row else {
        return Ok(None);
    };
    if stored_scope != scope
        || key != request.idempotency_key.as_str().as_bytes()
        || fingerprint != request.command_fingerprint.as_bytes()
    {
        return Err(Error::IdempotencyConflict);
    }
    match CommandOutcomeCodec
        .decode(&outcome)
        .map_err(|_| Error::CorruptData)?
    {
        runne_application::commands::CommandOutcome::TaskRunCancellationCompleted {
            taskrun_id: stored,
            new_version,
        } if stored == taskrun_id => {
            let event: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT event_id,payload FROM events
                     WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2 AND command_id=?3",
                    params![
                        taskrun_id.as_bytes(),
                        new_version as i64,
                        request.command_id.as_bytes()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| Error::CorruptData)?;
            let Some((event_id, payload)) = event else {
                return Err(Error::CorruptData);
            };
            let head: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT current_version,last_event_id FROM aggregate_streams
                     WHERE aggregate_type=1 AND aggregate_id=?1",
                    [taskrun_id.as_bytes()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| Error::CorruptData)?;
            if head != Some((new_version as i64, event_id))
                || TaskRunEventCodec
                    .decode(&payload)
                    .map_err(|_| Error::CorruptData)?
                    != TaskRunEvent::CancellationCompleted
            {
                return Err(Error::CorruptData);
            }
            Ok(Some(Receipt {
                taskrun_id,
                new_version,
            }))
        }
        _ => Err(Error::CorruptData),
    }
}

pub(super) fn command_id_exists(
    tx: &rusqlite::Transaction<'_>,
    command_id: CommandId,
) -> Result<bool, Error> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE command_id=?1)
          OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=?1)
          OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=?1)",
        [command_id.as_bytes()],
        |row| row.get(0),
    )
    .map_err(|_| Error::CorruptData)
}

pub(super) fn idempotency_key_exists(
    tx: &rusqlite::Transaction<'_>,
    scope: &[u8],
    key: &runne_domain::id::IdempotencyKey,
) -> Result<bool, Error> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM command_receipts
         WHERE idempotency_scope_bytes=?1 AND idempotency_key=?2)",
        params![scope, key.as_str().as_bytes()],
        |row| row.get(0),
    )
    .map_err(|_| Error::CorruptData)
}
