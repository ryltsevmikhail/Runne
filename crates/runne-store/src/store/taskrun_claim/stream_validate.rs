use super::*;
use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest};
use runne_domain::timestamp::Timestamp;
use rusqlite::OptionalExtension;

pub(crate) struct VerifiedTaskRunStream {
    pub(crate) version: u64,
    pub(crate) state: TaskRunState,
    pub(crate) active_attempt: Option<AttemptId>,
    pub(crate) is_v2_submission: bool,
    pub(crate) has_immutable_input: bool,
    pub(crate) events: Vec<EventEnvelope<TaskRunEvent>>,
}

pub(crate) fn verify_stream(
    connection: &rusqlite::Connection,
    id: TaskRunId,
    expected: Option<u64>,
) -> Result<VerifiedTaskRunStream, ClaimError> {
    let head: Option<(i64, Option<Vec<u8>>, Option<i64>)> = connection
        .query_row(
            "SELECT current_version,last_event_id,last_timestamp FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| ClaimError::CorruptData)?;
    let Some((current, last_id, last_time)) = head else {
        return match expected {
            Some(expected) => Err(ClaimError::StaleVersion {
                expected,
                actual: 0,
            }),
            None => Err(ClaimError::CorruptData),
        };
    };
    let version = u64::try_from(current).map_err(|_| ClaimError::CorruptData)?;
    if let Some(expected) = expected
        && version != expected
    {
        return Err(ClaimError::StaleVersion {
            expected,
            actual: version,
        });
    }
    let mut statement = connection
        .prepare(
            "SELECT event_id,sequence,global_position,timestamp,sensitivity,schema_version,causation_id,command_id,idempotency_key,actor,payload,integrity_digest,correlation_id,aggregate_id,correlation_type,integrity_profile FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
        )
        .map_err(|_| ClaimError::CorruptData)?;
    let rows = statement
        .query_map([id.as_bytes()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<Vec<u8>>>(6)?,
                r.get::<_, Vec<u8>>(7)?,
                r.get::<_, Vec<u8>>(8)?,
                r.get::<_, Vec<u8>>(9)?,
                r.get::<_, Vec<u8>>(10)?,
                r.get::<_, Vec<u8>>(11)?,
                r.get::<_, Vec<u8>>(12)?,
                r.get::<_, Vec<u8>>(13)?,
                r.get::<_, i64>(14)?,
                r.get::<_, i64>(15)?,
            ))
        })
        .map_err(|_| ClaimError::CorruptData)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ClaimError::CorruptData)?;
    if rows.len() as i64 != current || current == 0 {
        return Err(ClaimError::CorruptData);
    }
    let mut events: Vec<EventEnvelope<TaskRunEvent>> = Vec::with_capacity(rows.len());
    let codec = TaskRunEventCodec;
    let mut prior_position = 0;
    let mut prior_time = None;
    for (index, row) in rows.into_iter().enumerate() {
        let (
            eid,
            seq,
            pos,
            time,
            sensitivity,
            schema,
            causation,
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
            || prior_time.is_some_and(|v| time < v)
            || schema != 1
            || corr_type != 1
            || profile != 1
            || correlation.as_slice() != id.as_bytes()
            || aggregate.as_slice() != id.as_bytes()
            || pos <= 0
        {
            return Err(ClaimError::CorruptData);
        }
        let payload = codec.decode(&bytes).map_err(|_| ClaimError::CorruptData)?;
        let event_sensitivity = match sensitivity {
            0 => Sensitivity::Public,
            2 => Sensitivity::Sensitive,
            _ => return Err(ClaimError::CorruptData),
        };
        if !payload.accepts_sensitivity(event_sensitivity) {
            return Err(ClaimError::CorruptData);
        }
        let event = EventEnvelope::from_parts(
            EventId::from_bytes(uuid_bytes(eid)?),
            AggregateId::TaskRun(id),
            AggregateId::TaskRun(id),
            causation
                .map(uuid_bytes)
                .transpose()?
                .map(EventId::from_bytes),
            CommandId::from_bytes(uuid_bytes(command)?),
            IdempotencyKey::new(String::from_utf8(key).map_err(|_| ClaimError::CorruptData)?)
                .map_err(|_| ClaimError::CorruptData)?,
            u32::try_from(schema).map_err(|_| ClaimError::CorruptData)?,
            Actor::new(String::from_utf8(actor).map_err(|_| ClaimError::CorruptData)?)
                .map_err(|_| ClaimError::CorruptData)?,
            event_sensitivity,
            payload,
            u64::try_from(seq).map_err(|_| ClaimError::CorruptData)?,
            Timestamp::from_unix_micros(time),
            IntegrityDigest::from_bytes(uuid_or_digest(digest)?),
        );
        let encoded = codec
            .encode(event.payload())
            .map_err(|_| ClaimError::CorruptData)?;
        let expected_digest = compute_integrity_digest_with_global_position(&event, pos, &encoded)
            .map_err(|_| ClaimError::CorruptData)?;
        if event.integrity_digest() != &expected_digest
            || (index == 0 && event.causation_id().is_some())
            || (index > 0 && event.causation_id() != Some(events[index - 1].event_id()))
        {
            return Err(ClaimError::CorruptData);
        }
        prior_position = pos;
        prior_time = Some(time);
        events.push(event);
    }
    let last = events.last().ok_or(ClaimError::CorruptData)?;
    if last_id.as_deref() != Some(last.event_id().as_bytes().as_slice()) || last_time != prior_time
    {
        return Err(ClaimError::CorruptData);
    }
    let is_v2_submission = matches!(
        events.first().map(|event| event.payload()),
        Some(TaskRunEvent::TaskRunSubmitted { .. })
    );
    let has_immutable_input = matches!(
        events.first().map(|event| event.payload()),
        Some(TaskRunEvent::TaskRunSubmitted { .. })
    );
    let task = TaskRun::replay(&events).map_err(|_| ClaimError::CorruptData)?;
    Ok(VerifiedTaskRunStream {
        version,
        state: task.state(),
        active_attempt: task.active_attempt().copied(),
        is_v2_submission,
        has_immutable_input,
        events,
    })
}

/// Return the active attempt at one historical version after validating the
/// complete current stream's envelopes, integrity chain, and domain replay.
pub(crate) fn active_attempt_at_verified_version(
    connection: &rusqlite::Connection,
    id: TaskRunId,
    version: u64,
) -> Result<Option<AttemptId>, ClaimError> {
    let verified = verify_stream(connection, id, None)?;
    let end = usize::try_from(version).map_err(|_| ClaimError::CorruptData)?;
    if version == 0 || version > verified.version || end > verified.events.len() {
        return Err(ClaimError::CorruptData);
    }
    let prefix = TaskRun::replay(&verified.events[..end]).map_err(|_| ClaimError::CorruptData)?;
    Ok(prefix.active_attempt().copied())
}

fn uuid_bytes(bytes: Vec<u8>) -> Result<[u8; 16], ClaimError> {
    bytes.try_into().map_err(|_| ClaimError::CorruptData)
}

fn uuid_or_digest(bytes: Vec<u8>) -> Result<[u8; 32], ClaimError> {
    bytes.try_into().map_err(|_| ClaimError::CorruptData)
}
