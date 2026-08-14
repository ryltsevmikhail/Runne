use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    CORRELATION_TYPE_CONVERSATION, CORRELATION_TYPE_TASK_RUN, EventId, IntegrityDigest, RawRow,
    decode_conversation, decode_taskrun, invalid,
};

pub(crate) fn current_head_matches(
    transaction: &Transaction<'_>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    version: u64,
    event_id: &EventId,
    integrity: &IntegrityDigest,
    position: i64,
) -> rusqlite::Result<bool> {
    let stream = transaction
        .query_row(
            "SELECT current_version, last_event_id, last_timestamp FROM aggregate_streams
             WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![aggregate_type, aggregate_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((current, last_event_id, last_timestamp)) = stream else {
        return Ok(false);
    };
    if current != i64::try_from(version).map_err(|_| invalid())?
        || last_event_id.as_slice() != event_id.as_bytes()
        || transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE aggregate_type = ?1 AND aggregate_id = ?2 AND sequence > ?3)",
            params![aggregate_type, aggregate_id, current], |row| row.get::<_, bool>(0),
        )?
    {
        return Ok(false);
    }
    let row: Option<RawRow> = transaction.query_row(
        "SELECT event_id, sequence, global_position, timestamp, sensitivity, schema_version, causation_id,
                command_id, idempotency_key, actor, payload, integrity_digest, correlation_id,
                aggregate_id, correlation_type, integrity_profile FROM events
         WHERE aggregate_type = ?1 AND aggregate_id = ?2 AND sequence = ?3 AND event_id = ?4",
        params![aggregate_type, aggregate_id, current, event_id.as_bytes()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?,row.get(14)?,row.get(15)?)),
    ).optional()?;
    let Some(row) = row else {
        return Ok(false);
    };
    let (actual_id, actual_integrity, actual_position, actual_timestamp) = match aggregate_type {
        CORRELATION_TYPE_CONVERSATION => {
            let (event, event_position) = decode_conversation(
                gocode_domain::id::ConversationId::from_bytes(*aggregate_id),
                row,
            )?;
            (
                *event.event_id(),
                *event.integrity_digest(),
                event_position,
                event.timestamp().as_unix_micros(),
            )
        }
        CORRELATION_TYPE_TASK_RUN => {
            let (event, event_position) =
                decode_taskrun(gocode_domain::id::TaskRunId::from_bytes(*aggregate_id), row)?;
            (
                *event.event_id(),
                *event.integrity_digest(),
                event_position,
                event.timestamp().as_unix_micros(),
            )
        }
        _ => return Ok(false),
    };
    Ok(actual_id == *event_id
        && actual_integrity == *integrity
        && actual_position == position
        && actual_timestamp == last_timestamp)
}
