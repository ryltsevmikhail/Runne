use super::codec;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
};
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use rusqlite::{OptionalExtension, Transaction, params};

mod duplicate_event;
pub(crate) use duplicate_event::verify_duplicate_event;

type StopRow = (Vec<u8>, i64, i64, Vec<u8>);

pub(crate) fn ensure_not_stopped(
    tx: &Transaction<'_>,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    digest: &[u8],
) -> Result<(), EventStoreError> {
    match read_stop(tx, taskrun_id, attempt_id, digest)? {
        Some(_) => Err(EventStoreError::CorruptData),
        None => Ok(()),
    }
}
pub(crate) fn stop_reason(
    tx: &rusqlite::Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    digest: &[u8],
) -> Result<Option<u8>, EventStoreError> {
    read_stop(tx, taskrun_id, attempt_id, digest)
}
pub(crate) fn validate_duplicate_terminal(
    tx: &rusqlite::Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    digest: &[u8],
    event: &TaskRunEvent,
) -> Result<(), EventStoreError> {
    let reason = stop_reason(tx, taskrun_id, attempt_id, digest)?;
    let valid = match event {
        TaskRunEvent::CancellationCompleted => matches!(reason, Some(1..=5)),
        TaskRunEvent::TaskRunFailed { reason: value }
            if value == "local_command_policy_stopped_v1" =>
        {
            matches!(reason, Some(2..=5))
        }
        TaskRunEvent::TaskRunCompleted { .. } | TaskRunEvent::TaskRunFailed { .. } => {
            reason.is_none()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(EventStoreError::CorruptData)
    }
}

pub(super) fn read_binding(
    tx: &rusqlite::Connection,
    identity: &TaskRunAssignmentIdentity,
    binding: &LocalCommandPermissionBindingV1,
) -> Result<(Vec<u8>, codec::CaptureV1), EventStoreError> {
    let row: (Vec<u8>, Vec<u8>, i64, i64, i64) = tx
        .query_row(
            "SELECT b.binding_digest,b.binding,b.fence,r.route,r.provenance
         FROM x2_permission_bindings b JOIN taskrun_local_permission_routes r USING(taskrun_id)
         WHERE b.taskrun_id=?1 AND b.attempt_id=?2",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let record = codec::decode(&row.1).map_err(|_| EventStoreError::CorruptData)?;
    if !codec::digest_matches(&row.1, &row.0)
        || row.2 != identity.fence.0 as i64
        || row.3 != 2
        || row.4 != 3
        || record.taskrun_id != *identity.taskrun_id.as_bytes()
        || record.attempt_id != *identity.attempt_id.as_bytes()
        || record.canonical_binding_digest != *binding.digest().as_bytes()
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok((row.0, record))
}
pub(crate) fn stop_anchor(
    stream: &crate::store::taskrun_claim::stream_validate::VerifiedTaskRunStream,
    reason: u8,
) -> Result<(u64, Vec<u8>), EventStoreError> {
    let events = &stream.events;
    let index = match reason == 1 {
        true => events
            .iter()
            .rposition(|event| matches!(event.payload(), TaskRunEvent::CancellationRequested)),
        false => events.len().checked_sub(1),
    }
    .ok_or(EventStoreError::CorruptData)?;
    if reason == 1 && stream.state != TaskRunState::Cancelling {
        return Err(EventStoreError::CorruptData);
    }
    let event = &events[index];
    Ok((
        u64::try_from(index + 1).map_err(|_| EventStoreError::CorruptData)?,
        event.event_id().as_bytes().to_vec(),
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "stop evidence is persisted with its exact task, attempt, digest, event, and observation position"
)]
pub(crate) fn record_stop(
    tx: &Transaction<'_>,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    digest: &[u8],
    reason: u8,
    version: u64,
    event_id: &[u8],
    stopped_at: i64,
) -> Result<(), EventStoreError> {
    let version = i64::try_from(version).map_err(|_| EventStoreError::CorruptData)?;
    if !(1..=6).contains(&reason) || digest.len() != 32 || event_id.len() != 16 || version <= 0 {
        return Err(EventStoreError::CorruptData);
    }
    let event: Option<(i64, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT aggregate_type,aggregate_id,sequence FROM events WHERE event_id=?1",
            [event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if !event.is_some_and(|(aggregate, id, sequence)| {
        aggregate == 1 && id == taskrun_id && sequence == version
    }) {
        return Err(EventStoreError::CorruptData);
    }
    tx.execute(
        "INSERT INTO x2_permission_stop(taskrun_id,attempt_id,binding_digest,stop_id,reason,observed_version,event_id,stopped_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(taskrun_id,attempt_id) DO NOTHING",
        params![taskrun_id,attempt_id,digest,uuid::Uuid::now_v7().as_bytes(),i64::from(reason),version,event_id,stopped_at.max(1)],
    ).map_err(|_| EventStoreError::CorruptData)?;
    read_stop(tx, taskrun_id, attempt_id, digest)?.ok_or(EventStoreError::CorruptData)?;
    Ok(())
}

pub(super) fn read_stop(
    tx: &rusqlite::Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    digest: &[u8],
) -> Result<Option<u8>, EventStoreError> {
    let row: Option<StopRow> = tx
        .query_row(
            "SELECT binding_digest,reason,observed_version,event_id FROM x2_permission_stop
         WHERE taskrun_id=?1 AND attempt_id=?2",
            params![taskrun_id, attempt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((saved_digest, reason, version, event_id)) = row else {
        return Ok(None);
    };
    let reason = u8::try_from(reason).map_err(|_| EventStoreError::CorruptData)?;
    let event: Option<(i64, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT aggregate_type,aggregate_id,sequence FROM events WHERE event_id=?1",
            [&event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if saved_digest.as_slice() != digest
        || !(1..=6).contains(&reason)
        || version <= 0
        || !event.is_some_and(|(aggregate, id, sequence)| {
            aggregate == 1 && id == taskrun_id && sequence == version
        })
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(Some(reason))
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod tests;
