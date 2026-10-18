use super::LocalCommandRecoveryCandidate;
use crate::codec::{StoreCodec, TaskRunEventCodec};
use runne_application::ports::EventStoreError;
use runne_domain::task_run::TaskRunEvent;
use rusqlite::{OptionalExtension, params};

/// Exact already-settled check backing the idempotent completion branch: the
/// prior receipt, its terminal `CancellationCompleted` event at the stream
/// head, and the attempt's settled shape all match this candidate without any
/// new write. Independent of the recovery epoch, so a retry after a new
/// daemon generation stays inert.
pub(super) fn settled_cancellation_matches(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
) -> Result<bool, EventStoreError> {
    let taskrun = candidate.identity.taskrun_id.as_bytes();
    let receipt: Option<(Vec<u8>, i64, Vec<u8>)> = tx
        .query_row(
            "SELECT terminal_event_id,terminal_version,attempt_id
             FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?2",
            params![taskrun, candidate.identity.fence.0 as i64],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((event_id, terminal_version, attempt)) = receipt else {
        return Ok(false);
    };
    if attempt.as_slice() != candidate.identity.attempt_id.as_bytes() {
        return Ok(false);
    }
    let payload: Option<Vec<u8>> = tx
        .query_row(
            "SELECT payload FROM events
             WHERE event_id=?1 AND aggregate_type=1 AND aggregate_id=?2 AND sequence=?3",
            params![event_id, taskrun, terminal_version],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if !matches!(
        payload.and_then(|payload| TaskRunEventCodec.decode(&payload).ok()),
        Some(TaskRunEvent::CancellationCompleted)
    ) {
        return Ok(false);
    }
    settled_stream_and_attempt_match(tx, candidate, &event_id, terminal_version)
}

fn settled_stream_and_attempt_match(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
    event_id: &[u8],
    terminal_version: i64,
) -> Result<bool, EventStoreError> {
    let taskrun = candidate.identity.taskrun_id.as_bytes();
    let head: Option<(i64, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if head != Some((terminal_version, Some(event_id.to_vec()))) {
        return Ok(false);
    }
    let attempt_row: Option<(String, Option<i64>)> = tx
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4
               AND managed_area_identity=?5",
            params![
                taskrun,
                candidate.identity.attempt_id.as_bytes(),
                candidate.identity.node_epoch as i64,
                candidate.identity.fence.0 as i64,
                candidate.area_identity
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((state, exit)) = attempt_row else {
        return Ok(false);
    };
    if !matches!(state.as_str(), "cancelled" | "completed") {
        return Ok(false);
    }
    Ok(match exit {
        None => true,
        Some(code) => (0..=255).contains(&code),
    })
}
