use runne_application::ports::ProjectWorkspaceRepositoryError as Error;
use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use runne_domain::task_run::TaskRun;
use runne_domain::timestamp::Timestamp;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::codec::{StoreCodec, TaskRunEventCodec};
use crate::integrity::compute_integrity_digest_with_global_position;

type StoredEvent = (
    Vec<u8>,
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
    i64,
    i64,
    i64,
    i64,
);

pub(super) fn task_run_is_terminal(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
    origin_command_id: CommandId,
) -> Result<bool, Error> {
    let head = transaction
        .query_row(
            "SELECT current_version, last_event_id, last_timestamp FROM aggregate_streams
             WHERE aggregate_type = 1 AND aggregate_id = ?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::InvariantViolation)?;
    let version = u64::try_from(head.0).map_err(|_| Error::InvariantViolation)?;
    let stored = load_rows(transaction, taskrun_id)?;
    if version == 0 || stored.len() as u64 != version {
        return Err(Error::InvariantViolation);
    }
    let mut events = Vec::with_capacity(stored.len());
    let mut previous_position = 0_i64;
    let mut previous_timestamp = i64::MIN;
    for row in stored {
        let (envelope, global_position) = decode_row(taskrun_id, row)?;
        if global_position <= previous_position {
            return Err(Error::InvariantViolation);
        }
        if envelope.timestamp().as_unix_micros() < previous_timestamp {
            return Err(Error::InvariantViolation);
        }
        previous_position = global_position;
        previous_timestamp = envelope.timestamp().as_unix_micros();
        events.push(envelope);
    }
    let last = events.last().ok_or(Error::InvariantViolation)?;
    if events.first().map(|event| event.command_id()) != Some(&origin_command_id)
        || head.1.as_deref() != Some(last.event_id().as_bytes().as_slice())
        || head.2 != Some(last.timestamp().as_unix_micros())
    {
        return Err(Error::InvariantViolation);
    }
    let task_run = TaskRun::replay(&events).map_err(|_| Error::InvariantViolation)?;
    Ok(task_run.state().is_terminal())
}

fn load_rows(
    transaction: &Transaction<'_>,
    taskrun_id: TaskRunId,
) -> Result<Vec<StoredEvent>, Error> {
    let mut statement = transaction
        .prepare(
            "SELECT event_id, sequence, timestamp, schema_version, causation_id,
                    command_id, idempotency_key, actor, payload, integrity_digest,
                    correlation_id, correlation_type, integrity_profile,
                    global_position, sensitivity
             FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1 ORDER BY sequence",
        )
        .map_err(|_| Error::Unavailable)?;
    statement
        .query_map(params![taskrun_id.as_bytes()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
            ))
        })
        .map_err(|_| Error::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Error::Unavailable)
}

fn decode_row(
    taskrun_id: TaskRunId,
    row: StoredEvent,
) -> Result<(EventEnvelope<runne_domain::task_run::TaskRunEvent>, i64), Error> {
    let sequence = u64::try_from(row.1).map_err(|_| Error::InvariantViolation)?;
    let schema = u32::try_from(row.3).map_err(|_| Error::InvariantViolation)?;
    if schema != 1 || row.11 != 1 || row.12 != 1 || row.13 <= 0 {
        return Err(Error::InvariantViolation);
    }
    let event_id = valid_event_id(row.0)?;
    let command_id = valid_command_id(row.5)?;
    let causation = row.4.map(valid_event_id).transpose()?;
    let key = IdempotencyKey::new(String::from_utf8(row.6).map_err(|_| Error::InvariantViolation)?)
        .map_err(|_| Error::InvariantViolation)?;
    let actor = Actor::new(String::from_utf8(row.7).map_err(|_| Error::InvariantViolation)?)
        .map_err(|_| Error::InvariantViolation)?;
    if row.10 != taskrun_id.as_bytes() {
        return Err(Error::InvariantViolation);
    }
    let digest = IntegrityDigest::from_bytes(parse_array(row.9)?);
    let payload = TaskRunEventCodec
        .decode(&row.8)
        .map_err(|_| Error::InvariantViolation)?;
    let sensitivity = match row.14 {
        0 => Sensitivity::Public,
        2 => Sensitivity::Sensitive,
        _ => return Err(Error::InvariantViolation),
    };
    if !payload.accepts_sensitivity(sensitivity) {
        return Err(Error::InvariantViolation);
    }
    let envelope = EventEnvelope::from_parts(
        event_id,
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        causation,
        command_id,
        key,
        schema,
        actor,
        sensitivity,
        payload,
        sequence,
        Timestamp::from_unix_micros(row.2),
        digest,
    );
    let expected = compute_integrity_digest_with_global_position(&envelope, row.13, &row.8)
        .map_err(|_| Error::InvariantViolation)?;
    if expected != *envelope.integrity_digest() {
        return Err(Error::InvariantViolation);
    }
    Ok((envelope, row.13))
}

fn valid_event_id(bytes: Vec<u8>) -> Result<EventId, Error> {
    EventId::from_bytes(parse_array(bytes)?)
        .to_string()
        .parse()
        .map_err(|_| Error::InvariantViolation)
}

fn valid_command_id(bytes: Vec<u8>) -> Result<CommandId, Error> {
    CommandId::from_bytes(parse_array(bytes)?)
        .to_string()
        .parse()
        .map_err(|_| Error::InvariantViolation)
}

fn parse_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::InvariantViolation)
}
