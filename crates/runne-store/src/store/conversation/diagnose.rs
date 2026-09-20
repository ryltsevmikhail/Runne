//! NM-06 stream health classification: distinguishes a standard retention
//! gap (all present rows intact, only the stream header disagrees) from
//! corruption (a present row fails its row-level integrity checks).
//!
//! `load_conversation` fails fast with `EventStoreError::CorruptData` for
//! both shapes; this diagnostic classifies instead, so the delivery trust
//! gate can hand a genuine retention gap to the store's recovery contract
//! (410 + signed baseline) while corruption stays denied. The result is
//! content-free metadata only — never event payloads.

use super::super::parse_helpers::*;
use super::super::*;

/// Content-free classification of one conversation stream.
#[derive(Debug, Clone)]
pub enum ConversationStreamHealth {
    /// The stream replays: rows and header agree.
    Intact(ConversationLoadedStream),
    /// Every present row is intact, but the header disagrees with the rows:
    /// a standard retention gap (pruning or a removed prefix). Carries only
    /// counts, never payloads.
    RetentionGap {
        /// Logical version tracked in `aggregate_streams`.
        header_version: u64,
        /// Number of intact rows still present.
        retained_count: u64,
        /// Sequence of the first retained row (0 when no rows remain).
        first_retained_sequence: u64,
    },
    /// At least one present row failed decode, sensitivity, correlation, or
    /// digest verification. Row integrity outranks a header mismatch.
    Corrupt,
}

impl StoreTransaction {
    /// Classifies the conversation stream without failing fast on the header
    /// check. `Err(EventStoreError::NotFound)` = confirmed absence;
    /// `Err(EventStoreError::Unavailable)` = lock failure. Any row-level
    /// verification failure classifies as [`ConversationStreamHealth::Corrupt`].
    pub fn diagnose_conversation_stream(
        &self,
        conversation_id: ConversationId,
    ) -> Result<ConversationStreamHealth, EventStoreError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let stream = conn
            .query_row(
                "SELECT current_version, last_event_id
                 FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2",
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?
            .ok_or(EventStoreError::NotFound)?;
        let current_version = u64::try_from(stream.0).map_err(|_| EventStoreError::CorruptData)?;
        let last_event_id = stream.1.map(parse_event_id).transpose()?;

        let mut statement = conn
            .prepare(
                "SELECT event_id, sequence, global_position, timestamp, sensitivity,
                        schema_version, causation_id, command_id, idempotency_key,
                        actor, payload, integrity_digest, correlation_id,
                        correlation_type, integrity_profile
                 FROM events
                 WHERE aggregate_type = ?1 AND aggregate_id = ?2
                 ORDER BY sequence",
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let rows = statement
            .query_map(
                params![CORRELATION_TYPE_CONVERSATION, conversation_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, Vec<u8>>(11)?,
                        row.get::<_, Vec<u8>>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, i64>(14)?,
                    ))
                },
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let codec = ConversationEventCodec;
        let aggregate_id = AggregateId::Conversation(conversation_id);
        let mut events = Vec::new();

        for row in rows {
            let Ok(row) = row else {
                return Ok(ConversationStreamHealth::Corrupt);
            };
            match diagnose_row(row, &codec, &aggregate_id, conversation_id) {
                Some(event) => events.push(event),
                // Row integrity outranks a header mismatch: a present row
                // that fails verification is corruption, never a gap.
                None => return Ok(ConversationStreamHealth::Corrupt),
            }
        }

        let header_matches = events.len() as u64 == current_version
            && events
                .iter()
                .enumerate()
                .all(|(index, event)| event.sequence() == index as u64 + 1)
            && events.last().map(|event| *event.event_id()) == last_event_id;
        if header_matches {
            return Ok(ConversationStreamHealth::Intact(ConversationLoadedStream {
                events,
                current_version,
                last_event_id,
            }));
        }
        Ok(ConversationStreamHealth::RetentionGap {
            header_version: current_version,
            retained_count: events.len() as u64,
            first_retained_sequence: events.first().map_or(0, |event| event.sequence()),
        })
    }
}

/// Runs the per-row checks of `load_conversation` without failing fast.
/// Returns `None` when the row is corrupt.
#[allow(clippy::type_complexity)]
fn diagnose_row(
    row: (
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
        i64,
        i64,
    ),
    codec: &ConversationEventCodec,
    aggregate_id: &AggregateId,
    conversation_id: ConversationId,
) -> Option<EventEnvelope<ConversationEvent>> {
    let (
        event_id,
        sequence,
        global_position,
        timestamp,
        sensitivity,
        schema_version,
        causation_id,
        command_id,
        idempotency_key,
        actor,
        payload,
        stored_digest,
        correlation_id,
        correlation_type,
        integrity_profile,
    ) = row;
    if correlation_type != CORRELATION_TYPE_CONVERSATION
        || integrity_profile != INTEGRITY_PROFILE_V2
        || correlation_id.as_slice() != conversation_id.as_bytes()
    {
        return None;
    }
    let sequence = u64::try_from(sequence).ok()?;
    let schema_version = u32::try_from(schema_version).ok()?;
    let payload_value = codec.decode(&payload).ok()?;
    let sensitivity = stored_sensitivity(sensitivity).ok()?;
    if sensitivity != payload_value.sensitivity() {
        return None;
    }
    let event_id = parse_event_id(event_id).ok()?;
    let causation_id = causation_id.map(parse_event_id).transpose().ok()?;
    let command_id = parse_command_id(command_id).ok()?;
    let idempotency_key =
        runne_domain::id::IdempotencyKey::new(String::from_utf8(idempotency_key).ok()?).ok()?;
    let actor = Actor::new(String::from_utf8(actor).ok()?).ok()?;
    let stored_digest = parse_integrity_digest(stored_digest).ok()?;
    let envelope = EventEnvelope::from_parts(
        event_id,
        aggregate_id.clone(),
        aggregate_id.clone(),
        causation_id,
        command_id,
        idempotency_key,
        schema_version,
        actor,
        sensitivity,
        payload_value,
        sequence,
        Timestamp::from_unix_micros(timestamp),
        stored_digest,
    );
    let expected_digest =
        compute_integrity_digest_v2_with_global_position(&envelope, global_position, &payload)
            .ok()?;
    if envelope.integrity_digest() != &expected_digest {
        return None;
    }
    Some(envelope)
}
