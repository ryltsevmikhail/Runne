use super::super::super::parse_helpers::*;
use super::super::super::*;

pub(crate) fn load_conversation_from_connection(
    conn: &Connection,
    conversation_id: ConversationId,
) -> Result<ConversationLoadedStream, EventStoreError> {
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
        ) = row.map_err(|_| EventStoreError::CorruptData)?;
        if correlation_type != CORRELATION_TYPE_CONVERSATION
            || integrity_profile != INTEGRITY_PROFILE_V2
            || correlation_id.as_slice() != conversation_id.as_bytes()
        {
            return Err(EventStoreError::CorruptData);
        }
        let sequence = u64::try_from(sequence).map_err(|_| EventStoreError::CorruptData)?;
        let schema_version =
            u32::try_from(schema_version).map_err(|_| EventStoreError::CorruptData)?;
        let payload_value = codec
            .decode(&payload)
            .map_err(|_| EventStoreError::CorruptData)?;
        let sensitivity = stored_sensitivity(sensitivity)?;
        if sensitivity != payload_value.sensitivity() {
            return Err(EventStoreError::CorruptData);
        }
        let envelope = EventEnvelope::from_parts(
            parse_event_id(event_id)?,
            aggregate_id.clone(),
            aggregate_id.clone(),
            causation_id.map(parse_event_id).transpose()?,
            parse_command_id(command_id)?,
            runne_domain::id::IdempotencyKey::new(
                String::from_utf8(idempotency_key).map_err(|_| EventStoreError::CorruptData)?,
            )
            .map_err(|_| EventStoreError::CorruptData)?,
            schema_version,
            Actor::new(String::from_utf8(actor).map_err(|_| EventStoreError::CorruptData)?)
                .map_err(|_| EventStoreError::CorruptData)?,
            sensitivity,
            payload_value,
            sequence,
            Timestamp::from_unix_micros(timestamp),
            parse_integrity_digest(stored_digest)?,
        );
        let expected_digest =
            compute_integrity_digest_v2_with_global_position(&envelope, global_position, &payload)
                .map_err(|_| EventStoreError::CorruptData)?;
        if envelope.integrity_digest() != &expected_digest {
            return Err(EventStoreError::CorruptData);
        }
        events.push(envelope);
    }

    if events.len() as u64 != current_version
        || events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence() != index as u64 + 1)
        || events.last().map(|event| *event.event_id()) != last_event_id
    {
        return Err(EventStoreError::CorruptData);
    }

    Ok(ConversationLoadedStream {
        events,
        current_version,
        last_event_id,
    })
}
