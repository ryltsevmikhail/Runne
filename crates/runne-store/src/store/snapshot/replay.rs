use runne_api::{
    ReplayAggregateProjectionV1, ReplayPromotionProjectionViewV1,
    UnauthenticatedReplayProjectionV1, UnauthenticatedReplayPromotionProjectionV1,
};
use runne_domain::{conversation::Conversation, task_run::TaskRun};
use rusqlite::{Transaction, params};

use super::super::parse_helpers::*;
use super::super::*;

mod decode;
mod head;
mod promotion;
use decode::{decode_conversation, decode_taskrun, verify_head, verify_strict_position};
pub(crate) use head::current_head_matches;

pub(super) type RawRow = (
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

type StoredSnapshotRow = (
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
);

pub(super) fn invalid() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

pub(super) struct BuiltSnapshot {
    pub(super) projection: ReplayAggregateProjectionV1,
    pub(super) promotion_projection_bytes: Vec<u8>,
    pub(super) promotion_projection_digest: [u8; 32],
    pub(super) version: u64,
    pub(super) head_event_id: EventId,
    pub(super) head_integrity_digest: IntegrityDigest,
    pub(super) head_global_position: i64,
}

pub(super) fn build_snapshot(
    transaction: &Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
) -> rusqlite::Result<BuiltSnapshot> {
    let (version, last_event, last_timestamp) = transaction.query_row(
        "SELECT current_version, last_event_id, last_timestamp FROM aggregate_streams
         WHERE aggregate_type = ?1 AND aggregate_id = ?2",
        params![aggregate_type, aggregate_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        },
    )?;
    let version = u64::try_from(version).map_err(|_| invalid())?;
    if version == 0 {
        return Err(invalid());
    }
    let rows = load_rows(transaction, aggregate_type, aggregate_id)?;
    match aggregate_type {
        CORRELATION_TYPE_CONVERSATION => {
            conversation_snapshot(aggregate_id, version, last_event, last_timestamp, rows)
        }
        CORRELATION_TYPE_TASK_RUN => {
            taskrun_snapshot(aggregate_id, version, last_event, last_timestamp, rows)
        }
        _ => Err(invalid()),
    }
}

pub(super) fn parse_stored_projection(
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    row: StoredSnapshotRow,
) -> rusqlite::Result<super::StoredReplayProjection> {
    let (
        version,
        sequence,
        event_id,
        integrity,
        bytes,
        digest,
        promotion_codec,
        promotion_bytes,
        promotion_digest,
        position,
        snapshot_digest,
    ) = row;
    let aggregate_version = u64::try_from(version).map_err(|_| invalid())?;
    let event_sequence = u64::try_from(sequence).map_err(|_| invalid())?;
    if aggregate_version == 0 || aggregate_version != event_sequence || position <= 0 {
        return Err(invalid());
    }
    let projection = match aggregate_type {
        CORRELATION_TYPE_CONVERSATION => {
            UnauthenticatedReplayProjectionV1::decode_conversation_bytes(&bytes)
        }
        CORRELATION_TYPE_TASK_RUN => {
            UnauthenticatedReplayProjectionV1::decode_task_run_bytes(&bytes)
        }
        _ => return Err(invalid()),
    }
    .map_err(|_| invalid())?;
    if &projection.aggregate_id() != aggregate_id
        || projection.projection_digest().as_slice() != digest.as_slice()
    {
        return Err(invalid());
    }
    if promotion_codec != 1 {
        return Err(invalid());
    }
    let promotion_projection = UnauthenticatedReplayPromotionProjectionV1::decode(&promotion_bytes)
        .map_err(|_| invalid())?;
    let promotion_digest: [u8; 32] = promotion_digest.try_into().map_err(|_| invalid())?;
    let promotion_matches = match promotion_projection.view() {
        ReplayPromotionProjectionViewV1::Conversation(view) => {
            aggregate_type == CORRELATION_TYPE_CONVERSATION
                && view.aggregate_id() == *aggregate_id
                && view.projection_digest() == &promotion_digest
        }
        ReplayPromotionProjectionViewV1::TaskRun(view) => {
            aggregate_type == CORRELATION_TYPE_TASK_RUN
                && view.aggregate_id() == *aggregate_id
                && view.promotion_digest() == &promotion_digest
        }
    };
    if !promotion_matches {
        return Err(invalid());
    }
    let event_id = parse_event_id(event_id).map_err(|_| invalid())?;
    let integrity = parse_integrity_digest(integrity).map_err(|_| invalid())?;
    let snapshot_digest: [u8; 32] = snapshot_digest.try_into().map_err(|_| invalid())?;
    let expected = super::integrity::snapshot_integrity_digest(
        aggregate_type,
        aggregate_id,
        aggregate_version,
        event_sequence,
        event_id.as_bytes(),
        integrity.as_bytes(),
        position,
        projection.projection_digest(),
        projection.encoded_bytes(),
        &promotion_digest,
        &promotion_bytes,
    )
    .ok_or_else(invalid)?;
    if snapshot_digest != expected {
        return Err(invalid());
    }
    Ok(super::StoredReplayProjection {
        projection,
        promotion_projection,
        promotion_projection_bytes: promotion_bytes,
        aggregate_version,
        event_sequence,
        head_event_id: event_id,
        head_integrity_digest: integrity,
        head_global_position: position,
    })
}

fn conversation_snapshot(
    aggregate_id: &[u8; 16],
    version: u64,
    last_event: Option<Vec<u8>>,
    last_timestamp: Option<i64>,
    rows: Vec<RawRow>,
) -> rusqlite::Result<BuiltSnapshot> {
    let id = runne_domain::id::ConversationId::from_bytes(*aggregate_id);
    let mut events = Vec::with_capacity(rows.len());
    let mut head = None;
    let mut prior_position = 0;
    for row in rows {
        let (event, position) = decode_conversation(id, row)?;
        verify_strict_position(prior_position, position)?;
        prior_position = position;
        head = Some((
            *event.event_id(),
            *event.integrity_digest(),
            position,
            event.timestamp().as_unix_micros(),
        ));
        events.push(event);
    }
    let (event_id, integrity, position, _) =
        verify_head(version, last_event, last_timestamp, &events, head)?;
    let aggregate = Conversation::replay(&events).map_err(|_| invalid())?;
    let projection =
        ReplayAggregateProjectionV1::from_conversation(&aggregate).map_err(|_| invalid())?;
    let promotion_snapshot = aggregate.snapshot_v1();
    let (promotion_projection_bytes, promotion_projection_digest) =
        promotion::conversation_projection(&promotion_snapshot, &events)?;
    Ok(BuiltSnapshot {
        projection,
        promotion_projection_bytes,
        promotion_projection_digest,
        version,
        head_event_id: event_id,
        head_integrity_digest: integrity,
        head_global_position: position,
    })
}

fn taskrun_snapshot(
    aggregate_id: &[u8; 16],
    version: u64,
    last_event: Option<Vec<u8>>,
    last_timestamp: Option<i64>,
    rows: Vec<RawRow>,
) -> rusqlite::Result<BuiltSnapshot> {
    let id = runne_domain::id::TaskRunId::from_bytes(*aggregate_id);
    let mut events = Vec::with_capacity(rows.len());
    let mut head = None;
    let mut prior_position = 0;
    for row in rows {
        let (event, position) = decode_taskrun(id, row)?;
        verify_strict_position(prior_position, position)?;
        prior_position = position;
        head = Some((
            *event.event_id(),
            *event.integrity_digest(),
            position,
            event.timestamp().as_unix_micros(),
        ));
        events.push(event);
    }
    let (event_id, integrity, position, _) =
        verify_head(version, last_event, last_timestamp, &events, head)?;
    let aggregate = TaskRun::replay(&events).map_err(|_| invalid())?;
    let projection =
        ReplayAggregateProjectionV1::from_task_run(&aggregate).map_err(|_| invalid())?;
    let promotion_snapshot = aggregate.snapshot_v1();
    let (promotion_projection_bytes, promotion_projection_digest) =
        promotion::taskrun_projection(&promotion_snapshot)?;
    Ok(BuiltSnapshot {
        projection,
        promotion_projection_bytes,
        promotion_projection_digest,
        version,
        head_event_id: event_id,
        head_integrity_digest: integrity,
        head_global_position: position,
    })
}

fn load_rows(
    transaction: &Transaction<'_>,
    kind: i64,
    id: &[u8; 16],
) -> rusqlite::Result<Vec<RawRow>> {
    transaction.prepare("SELECT event_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, payload, integrity_digest, correlation_id, aggregate_id, correlation_type, integrity_profile FROM events WHERE aggregate_type = ?1 AND aggregate_id = ?2 ORDER BY sequence")?
        .query_map(params![kind, id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?)))?
        .collect()
}
