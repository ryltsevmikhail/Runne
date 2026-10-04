use super::*;
use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{AggregateId, IdempotencyKey};
use rusqlite::OptionalExtension;

type EventRow = (
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
);

pub(super) fn verify_claim_stream(
    connection: &Connection,
    receipt: &TaskRunClaimReceipt,
    command_id: CommandId,
    idempotency_key: &[u8],
) -> Result<(), ClaimError> {
    verify_claim_stream_inner(connection, receipt, command_id, idempotency_key).map(|_| ())
}

pub(super) fn verify_claim_stream_task(
    connection: &Connection,
    receipt: &TaskRunClaimReceipt,
    command_id: CommandId,
    idempotency_key: &[u8],
) -> Result<TaskRun, ClaimError> {
    verify_claim_stream_inner(connection, receipt, command_id, idempotency_key)
}

pub(super) fn verify_released_stream(
    connection: &Connection,
    receipt: &TaskRunClaimReceipt,
    command_id: CommandId,
    idempotency_key: &[u8],
    release_event_id: EventId,
    release_version: u64,
    release: ReleaseEventMetadata<'_>,
) -> Result<(), ClaimError> {
    let task = verify_claim_stream_inner(connection, receipt, command_id, idempotency_key)?;
    let head: Vec<u8> = connection.query_row(
        "SELECT last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
        [receipt.taskrun_id.as_bytes()], |row| row.get(0),
    ).map_err(|_| ClaimError::CorruptData)?;
    let (payload, command, key, cause): (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) = connection.query_row(
        "SELECT payload,command_id,idempotency_key,causation_id FROM events WHERE event_id=?1 AND aggregate_type=1 AND aggregate_id=?2 AND sequence=?3",
        rusqlite::params![release_event_id.as_bytes(),receipt.taskrun_id.as_bytes(),release_version as i64], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).map_err(|_| ClaimError::CorruptData)?;
    let event = TaskRunEventCodec
        .decode(&payload)
        .map_err(|_| ClaimError::CorruptData)?;
    if task.state() != TaskRunState::Failed
        || head.as_slice() != release_event_id.as_bytes()
        || command.as_slice() != release.command_id.as_bytes()
        || key != release.idempotency_key
        || cause.as_deref() != Some(receipt.started_event_id.as_bytes())
        || event
            != (TaskRunEvent::TaskRunFailed {
                reason: "dispatch_not_started".into(),
            })
    {
        return Err(ClaimError::CorruptData);
    }
    Ok(())
}

fn verify_claim_stream_inner(
    connection: &Connection,
    receipt: &TaskRunClaimReceipt,
    command_id: CommandId,
    idempotency_key: &[u8],
) -> Result<TaskRun, ClaimError> {
    let id = receipt.taskrun_id;
    let version = i64::try_from(receipt.new_version).map_err(|_| ClaimError::CorruptData)?;
    if version < 2 {
        return Err(ClaimError::CorruptData);
    }
    let head: Option<(i64, Option<Vec<u8>>, Option<i64>)> = connection
        .query_row(
            "SELECT current_version,last_event_id,last_timestamp FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| ClaimError::CorruptData)?;
    let Some((current, last_id, last_time)) = head else {
        return Err(ClaimError::CorruptData);
    };
    if current < version || current <= 0 {
        return Err(ClaimError::CorruptData);
    }
    let rows = connection
        .prepare(
            "SELECT event_id,sequence,global_position,timestamp,sensitivity,schema_version,causation_id,command_id,idempotency_key,actor,payload,integrity_digest,correlation_id,aggregate_id,correlation_type,integrity_profile FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
        )
        .map_err(|_| ClaimError::CorruptData)?
        .query_map([id.as_bytes()], |row| {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?,
                row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?,
                row.get(12)?, row.get(13)?, row.get(14)?, row.get(15)?,
            ))
        })
        .map_err(|_| ClaimError::CorruptData)?
        .collect::<rusqlite::Result<Vec<EventRow>>>()
        .map_err(|_| ClaimError::CorruptData)?;
    if rows.len() as i64 != current {
        return Err(ClaimError::CorruptData);
    }
    let mut prior_event = None;
    let mut prior_position = 0;
    let mut prior_time = None;
    let mut claim_events = Vec::new();
    let mut replay_events = Vec::with_capacity(rows.len());
    let codec = TaskRunEventCodec;
    for (index, row) in rows.into_iter().enumerate() {
        let (
            eid,
            seq,
            pos,
            time,
            sensitivity,
            schema,
            cause,
            command,
            key,
            actor,
            bytes,
            digest,
            correlation,
            aggregate,
            corr_type,
            profile,
        ) = row;
        if seq != index as i64 + 1
            || pos <= prior_position
            || pos <= 0
            || prior_time.is_some_and(|value| time < value)
            || schema != 1
            || corr_type != 1
            || profile != 1
            || correlation.as_slice() != id.as_bytes()
            || aggregate.as_slice() != id.as_bytes()
        {
            return Err(ClaimError::CorruptData);
        }
        let event_id = EventId::from_bytes(array16(eid)?);
        let command = CommandId::from_bytes(array16(command)?);
        let key_text = String::from_utf8(key.clone()).map_err(|_| ClaimError::CorruptData)?;
        let key_value = IdempotencyKey::new(key_text).map_err(|_| ClaimError::CorruptData)?;
        let actor = Actor::new(String::from_utf8(actor).map_err(|_| ClaimError::CorruptData)?)
            .map_err(|_| ClaimError::CorruptData)?;
        let payload = codec.decode(&bytes).map_err(|_| ClaimError::CorruptData)?;
        let sensitivity = match (sensitivity, &payload) {
            (0, value) if !matches!(value, TaskRunEvent::TaskRunSubmitted { .. }) => {
                Sensitivity::Public
            }
            (2, TaskRunEvent::TaskRunSubmitted { .. }) => Sensitivity::Sensitive,
            _ => return Err(ClaimError::CorruptData),
        };
        let event = EventEnvelope::from_parts(
            event_id,
            AggregateId::TaskRun(id),
            AggregateId::TaskRun(id),
            cause.map(array16).transpose()?.map(EventId::from_bytes),
            command,
            key_value,
            u32::try_from(schema).map_err(|_| ClaimError::CorruptData)?,
            actor,
            sensitivity,
            payload,
            u64::try_from(seq).map_err(|_| ClaimError::CorruptData)?,
            Timestamp::from_unix_micros(time),
            IntegrityDigest::from_bytes(array32(digest)?),
        );
        let payload = codec
            .encode(event.payload())
            .map_err(|_| ClaimError::CorruptData)?;
        if event.integrity_digest()
            != &compute_integrity_digest_with_global_position(&event, pos, &payload)
                .map_err(|_| ClaimError::CorruptData)?
            || (index == 0 && event.causation_id().is_some())
            || (index > 0 && event.causation_id().copied() != prior_event)
        {
            return Err(ClaimError::CorruptData);
        }
        if seq == version - 1 || seq == version {
            claim_events.push((seq, event.clone(), key));
        }
        replay_events.push(event);
        prior_event = Some(event_id);
        prior_position = pos;
        prior_time = Some(time);
    }
    if last_id.as_deref()
        != prior_event
            .as_ref()
            .map(|event| event.as_bytes().as_slice())
        || last_time != prior_time
    {
        return Err(ClaimError::CorruptData);
    }
    if claim_events.len() != 2 {
        return Err(ClaimError::CorruptData);
    }
    let task = TaskRun::replay(&replay_events).map_err(|_| ClaimError::CorruptData)?;
    if !task.attempt_history().contains(&receipt.attempt_id) {
        return Err(ClaimError::CorruptData);
    }
    let (admit_seq, admitted, admitted_key) = &claim_events[0];
    let (start_seq, started, started_key) = &claim_events[1];
    if *admit_seq != version - 1
        || *start_seq != version
        || admitted.event_id() != &receipt.admitted_event_id
        || started.event_id() != &receipt.started_event_id
        || admitted.payload() != &TaskRunEvent::TaskRunAdmitted
        || started.payload()
            != &(TaskRunEvent::AttemptStarted {
                attempt_id: receipt.attempt_id,
            })
        || admitted.command_id() != &command_id
        || started.command_id() != &command_id
        || admitted_key.as_slice() != idempotency_key
        || started_key.as_slice() != idempotency_key
        || admitted
            .causation_id()
            .is_some_and(|id| id == &receipt.started_event_id)
        || started.causation_id() != Some(&receipt.admitted_event_id)
    {
        return Err(ClaimError::CorruptData);
    }
    Ok(task)
}

fn array16(value: Vec<u8>) -> Result<[u8; 16], ClaimError> {
    value.try_into().map_err(|_| ClaimError::CorruptData)
}

fn array32(value: Vec<u8>) -> Result<[u8; 32], ClaimError> {
    value.try_into().map_err(|_| ClaimError::CorruptData)
}
