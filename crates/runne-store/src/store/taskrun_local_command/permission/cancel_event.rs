use runne_application::ports::{EventStoreError, TaskRunAssignmentIdentity};
use runne_domain::event::{Actor, Sensitivity, UncommittedEvent};
use runne_domain::id::{AggregateId, CommandId, EventId, IdempotencyKey};
use runne_domain::task_run::TaskRunEvent;

/// Terminal append facts for the pre-release cancellation completion.
pub(super) struct CancellationEvent {
    pub(super) event: UncommittedEvent<TaskRunEvent>,
    pub(super) stream_version: i64,
    pub(super) sequence: u64,
    pub(super) position: i64,
    pub(super) last_event: Vec<u8>,
    pub(super) last_timestamp: i64,
}

pub(super) fn cancellation_event(
    identity: &TaskRunAssignmentIdentity,
    tx: &rusqlite::Transaction<'_>,
) -> Result<CancellationEvent, EventStoreError> {
    let taskrun = identity.taskrun_id.as_bytes();
    let (stream_version, last_event, last_timestamp): (i64, Vec<u8>, i64) = tx
        .query_row(
            "SELECT current_version,last_event_id,last_timestamp FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let causation: [u8; 16] = last_event
        .as_slice()
        .try_into()
        .map_err(|_| EventStoreError::CorruptData)?;
    let aggregate = AggregateId::TaskRun(identity.taskrun_id);
    let key = IdempotencyKey::new(format!(
        "local-command-cancel-before-release-v1:{}:{}",
        identity.taskrun_id, identity.fence.0
    ))
    .map_err(|_| EventStoreError::CorruptData)?;
    let event = UncommittedEvent::from_parts(
        EventId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        aggregate.clone(),
        aggregate,
        Some(EventId::from_bytes(causation)),
        CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        key,
        1,
        Actor::new("system:local_command_worker").map_err(|_| EventStoreError::CorruptData)?,
        Sensitivity::Public,
        TaskRunEvent::CancellationCompleted,
    );
    let position: i64 = tx
        .query_row(
            "SELECT next_global_position FROM event_log_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let sequence = stream_version
        .checked_add(1)
        .ok_or(EventStoreError::CorruptData)?;
    Ok(CancellationEvent {
        event,
        stream_version,
        sequence: u64::try_from(sequence).map_err(|_| EventStoreError::CorruptData)?,
        position,
        last_event,
        last_timestamp,
    })
}
