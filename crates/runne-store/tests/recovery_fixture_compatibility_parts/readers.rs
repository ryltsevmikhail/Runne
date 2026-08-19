use std::collections::BTreeMap;
use std::path::Path;

use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{
    AggregateId, CommandId, ConversationId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use runne_domain::timestamp::Timestamp;
use runne_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use runne_store::integrity::{
    compute_integrity_digest_v2_with_global_position, compute_integrity_digest_with_global_position,
};
use rusqlite::{Connection, OpenFlags};

#[path = "reader_provider_prepared.rs"]
mod provider_prepared;
#[path = "reader_snapshot.rs"]
mod snapshot;

pub(crate) use provider_prepared::validate_provider_prepared;
use snapshot::snapshot;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FixtureValidationError {
    UnknownProfile,
    Corrupt,
}

struct EventRow {
    event_id: Vec<u8>,
    aggregate_type: i64,
    aggregate_id: Vec<u8>,
    sequence: i64,
    global_position: i64,
    timestamp: i64,
    sensitivity: i64,
    schema_version: i64,
    causation_id: Option<Vec<u8>>,
    command_id: Vec<u8>,
    idempotency_key: Vec<u8>,
    actor: Vec<u8>,
    payload: Vec<u8>,
    integrity_digest: Vec<u8>,
    correlation_id: Vec<u8>,
    correlation_type: i64,
    integrity_profile: i64,
}

pub(crate) fn validate_events(
    path: &Path,
    expected_profile: u16,
) -> Result<Vec<BTreeMap<String, String>>, FixtureValidationError> {
    let connection = readonly(path)?;
    let rows = event_rows(&connection)?;
    let mut snapshots = Vec::with_capacity(rows.len());
    for row in rows {
        if row.integrity_profile != i64::from(expected_profile) {
            return Err(FixtureValidationError::UnknownProfile);
        }
        match expected_profile {
            1 => validate_v1(&row)?,
            2 => validate_v2(&row)?,
            _ => return Err(FixtureValidationError::UnknownProfile),
        }
        snapshots.push(snapshot(&row));
    }
    Ok(snapshots)
}

pub(crate) fn schema_versions(path: &Path) -> Result<(i64, i64), FixtureValidationError> {
    let connection = readonly(path)?;
    Ok((
        pragma(&connection, "schema_version")?,
        pragma(&connection, "user_version")?,
    ))
}

pub(crate) fn sidecars(path: &Path) -> (bool, bool) {
    let base = path.to_string_lossy();
    (
        Path::new(&format!("{base}-wal")).exists(),
        Path::new(&format!("{base}-shm")).exists(),
    )
}

pub(crate) fn v2_digest_for_first_v1_event(
    path: &Path,
) -> Result<[u8; 32], FixtureValidationError> {
    let connection = readonly(path)?;
    let row = event_rows(&connection)?
        .into_iter()
        .next()
        .ok_or(FixtureValidationError::Corrupt)?;
    let taskrun_id = TaskRunId::from_bytes(fixed(&row.correlation_id)?);
    let event = EventEnvelope::from_parts(
        EventId::from_bytes(fixed(&row.event_id)?),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        row.causation_id
            .as_deref()
            .map(fixed)
            .transpose()?
            .map(EventId::from_bytes),
        CommandId::from_bytes(fixed(&row.command_id)?),
        key(&row.idempotency_key)?,
        row.schema_version
            .try_into()
            .map_err(|_| FixtureValidationError::Corrupt)?,
        actor(&row.actor)?,
        Sensitivity::Public,
        TaskRunEventCodec
            .decode(&row.payload)
            .map_err(|_| FixtureValidationError::Corrupt)?,
        row.sequence
            .try_into()
            .map_err(|_| FixtureValidationError::Corrupt)?,
        Timestamp::from_unix_micros(row.timestamp),
        IntegrityDigest::from_bytes([0; 32]),
    );
    Ok(
        *compute_integrity_digest_v2_with_global_position(
            &event,
            row.global_position,
            &row.payload,
        )
        .map_err(|_| FixtureValidationError::Corrupt)?
        .as_bytes(),
    )
}

fn validate_v1(row: &EventRow) -> Result<(), FixtureValidationError> {
    if row.aggregate_type != 1
        || row.correlation_type != 1
        || row.sensitivity != 0
        || row.aggregate_id != row.correlation_id
    {
        return Err(FixtureValidationError::Corrupt);
    }
    let taskrun_id = TaskRunId::from_bytes(fixed(&row.correlation_id)?);
    let payload = TaskRunEventCodec
        .decode(&row.payload)
        .map_err(|_| FixtureValidationError::Corrupt)?;
    let event = envelope(
        row,
        AggregateId::TaskRun(taskrun_id),
        payload,
        Sensitivity::Public,
    )?;
    let expected =
        compute_integrity_digest_with_global_position(&event, row.global_position, &row.payload)
            .map_err(|_| FixtureValidationError::Corrupt)?;
    if expected.as_bytes() == fixed::<32>(&row.integrity_digest)?.as_slice() {
        Ok(())
    } else {
        Err(FixtureValidationError::Corrupt)
    }
}

fn validate_v2(row: &EventRow) -> Result<(), FixtureValidationError> {
    if row.aggregate_type != 2
        || row.correlation_type != 2
        || row.aggregate_id != row.correlation_id
    {
        return Err(FixtureValidationError::Corrupt);
    }
    let conversation_id = ConversationId::from_bytes(fixed(&row.correlation_id)?);
    let payload = ConversationEventCodec
        .decode(&row.payload)
        .map_err(|_| FixtureValidationError::Corrupt)?;
    let sensitivity = sensitivity(row.sensitivity)?;
    if payload.sensitivity() != sensitivity {
        return Err(FixtureValidationError::Corrupt);
    }
    let event = envelope(
        row,
        AggregateId::Conversation(conversation_id),
        payload,
        sensitivity,
    )?;
    let expected =
        compute_integrity_digest_v2_with_global_position(&event, row.global_position, &row.payload)
            .map_err(|_| FixtureValidationError::Corrupt)?;
    if expected.as_bytes() == fixed::<32>(&row.integrity_digest)?.as_slice() {
        Ok(())
    } else {
        Err(FixtureValidationError::Corrupt)
    }
}

fn envelope<E>(
    row: &EventRow,
    aggregate_id: AggregateId,
    payload: E,
    sensitivity: Sensitivity,
) -> Result<EventEnvelope<E>, FixtureValidationError> {
    Ok(EventEnvelope::from_parts(
        EventId::from_bytes(fixed(&row.event_id)?),
        aggregate_id.clone(),
        aggregate_id,
        row.causation_id
            .as_deref()
            .map(fixed)
            .transpose()?
            .map(EventId::from_bytes),
        CommandId::from_bytes(fixed(&row.command_id)?),
        key(&row.idempotency_key)?,
        row.schema_version
            .try_into()
            .map_err(|_| FixtureValidationError::Corrupt)?,
        actor(&row.actor)?,
        sensitivity,
        payload,
        row.sequence
            .try_into()
            .map_err(|_| FixtureValidationError::Corrupt)?,
        Timestamp::from_unix_micros(row.timestamp),
        IntegrityDigest::from_bytes(fixed(&row.integrity_digest)?),
    ))
}

fn event_rows(connection: &Connection) -> Result<Vec<EventRow>, FixtureValidationError> {
    let mut statement = connection.prepare("SELECT event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, correlation_type, integrity_profile FROM events ORDER BY global_position").map_err(|_| FixtureValidationError::Corrupt)?;
    statement
        .query_map([], |row| {
            Ok(EventRow {
                event_id: row.get(0)?,
                aggregate_type: row.get(1)?,
                aggregate_id: row.get(2)?,
                sequence: row.get(3)?,
                global_position: row.get(4)?,
                timestamp: row.get(5)?,
                sensitivity: row.get(6)?,
                schema_version: row.get(7)?,
                causation_id: row.get(8)?,
                command_id: row.get(9)?,
                idempotency_key: row.get(10)?,
                actor: row.get(11)?,
                payload: row.get(12)?,
                integrity_digest: row.get(13)?,
                correlation_id: row.get(14)?,
                correlation_type: row.get(15)?,
                integrity_profile: row.get(16)?,
            })
        })
        .map_err(|_| FixtureValidationError::Corrupt)?
        .collect::<Result<_, _>>()
        .map_err(|_| FixtureValidationError::Corrupt)
}

fn readonly(path: &Path) -> Result<Connection, FixtureValidationError> {
    let uri = format!("file:{}?immutable=1", path.to_string_lossy());
    Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| FixtureValidationError::Corrupt)
}
fn pragma(connection: &Connection, name: &str) -> Result<i64, FixtureValidationError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(|_| FixtureValidationError::Corrupt)
}
fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], FixtureValidationError> {
    value
        .try_into()
        .map_err(|_| FixtureValidationError::Corrupt)
}
fn key(value: &[u8]) -> Result<IdempotencyKey, FixtureValidationError> {
    IdempotencyKey::new(std::str::from_utf8(value).map_err(|_| FixtureValidationError::Corrupt)?)
        .map_err(|_| FixtureValidationError::Corrupt)
}
fn actor(value: &[u8]) -> Result<Actor, FixtureValidationError> {
    Actor::new(std::str::from_utf8(value).map_err(|_| FixtureValidationError::Corrupt)?)
        .map_err(|_| FixtureValidationError::Corrupt)
}
fn sensitivity(value: i64) -> Result<Sensitivity, FixtureValidationError> {
    match value {
        0 => Ok(Sensitivity::Public),
        1 => Ok(Sensitivity::Internal),
        2 => Ok(Sensitivity::Sensitive),
        _ => Err(FixtureValidationError::Corrupt),
    }
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
