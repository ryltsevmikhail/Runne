use super::super::LocalCommandRecoveryCandidate;
use runne_application::ports::EventStoreError;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::event::UncommittedEvent;
use runne_domain::id::AggregateId;
use runne_domain::task_run::TaskRunEvent;
use rusqlite::{OptionalExtension, Transaction};

/// Appends the terminal, preserving the generic guard for legacy routes.
///
/// The caller has already revalidated the exact empty area and recovery owner,
/// checked the historical assignment and active running attempt, and appended
/// `ReconciliationStarted` through the ordinary event guard in this transaction.
#[allow(clippy::too_many_arguments)]
pub(super) fn append_terminal(
    tx: &Transaction<'_>,
    prohibited_content: &dyn ProhibitedContentPort,
    candidate: &LocalCommandRecoveryCandidate,
    stream_version: i64,
    previous_head: &[u8],
    reconciliation: &UncommittedEvent<TaskRunEvent>,
    terminal: &UncommittedEvent<TaskRunEvent>,
    reconciliation_sequence: i64,
    terminal_sequence: i64,
    reconciliation_position: i64,
    terminal_position: i64,
    timestamp: i64,
) -> Result<(), EventStoreError> {
    let taskrun_id = candidate.identity.taskrun_id;
    let route: Option<(i64, i64, i64)> = tx
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    match route {
        Some((2, 3, 68)) => {}
        Some((1, 1, 68)) | Some((1, 2, 68)) => {
            return crate::store::event_guard::append_taskrun_event(
                tx,
                prohibited_content,
                terminal,
                u64::try_from(terminal_sequence).map_err(|_| EventStoreError::CorruptData)?,
                terminal_position,
                timestamp,
            )
            .map_err(|_| EventStoreError::CorruptData);
        }
        _ => return Err(EventStoreError::CorruptData),
    }

    let task = AggregateId::TaskRun(taskrun_id);
    let first_sequence = stream_version
        .checked_add(1)
        .ok_or(EventStoreError::CorruptData)?;
    let expected_terminal_sequence = stream_version
        .checked_add(2)
        .ok_or(EventStoreError::CorruptData)?;
    let expected_terminal_position = reconciliation_position
        .checked_add(1)
        .ok_or(EventStoreError::CorruptData)?;
    let expected_first_cause: [u8; 16] = previous_head
        .try_into()
        .map_err(|_| EventStoreError::CorruptData)?;
    if reconciliation_sequence != first_sequence
        || terminal_sequence != expected_terminal_sequence
        || terminal_position != expected_terminal_position
        || reconciliation.aggregate_id() != &task
        || reconciliation.correlation_id() != &task
        || reconciliation
            .causation_id()
            .map(|id| id.as_bytes().as_slice())
            != Some(expected_first_cause.as_slice())
        || reconciliation.payload() != &TaskRunEvent::ReconciliationStarted
        || terminal.aggregate_id() != &task
        || terminal.correlation_id() != &task
        || terminal.causation_id() != Some(reconciliation.event_id())
        || terminal.payload() != &TaskRunEvent::Unrecoverable
        || terminal.command_id() != reconciliation.command_id()
        || terminal.idempotency_key() != reconciliation.idempotency_key()
    {
        return Err(EventStoreError::CorruptData);
    }

    let (current_version, current_head): (i64, Vec<u8>) = tx
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if current_version != stream_version || current_head.as_slice() != previous_head {
        return Err(EventStoreError::CorruptData);
    }

    let sequence = u64::try_from(terminal_sequence).map_err(|_| EventStoreError::CorruptData)?;
    let (payload, digest, guarded_taskrun_id) = crate::store::event_guard::guard_taskrun_event(
        prohibited_content,
        terminal,
        sequence,
        terminal_position,
        timestamp,
    )
    .map_err(|_| EventStoreError::CorruptData)?;
    if guarded_taskrun_id != taskrun_id {
        return Err(EventStoreError::CorruptData);
    }
    crate::store::append_helpers::insert_event(
        tx,
        terminal,
        super::super::super::super::CORRELATION_TYPE_TASK_RUN,
        guarded_taskrun_id.as_bytes(),
        sequence,
        terminal_position,
        timestamp,
        &payload,
        digest,
        super::super::super::super::INTEGRITY_PROFILE_V1,
    )
    .map_err(|_| EventStoreError::CorruptData)
}
