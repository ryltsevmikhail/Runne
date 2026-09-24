use runne_domain::event::{Actor, EventEnvelope, Sensitivity};
use runne_domain::id::{AggregateId, IdempotencyKey, IntegrityDigest};
use runne_domain::timestamp::Timestamp;

use super::super::super::parse_helpers::*;
use super::super::super::*;
use super::{RawRow, invalid};

pub(super) fn decode_conversation(
    id: runne_domain::id::ConversationId,
    row: RawRow,
) -> rusqlite::Result<(EventEnvelope<ConversationEvent>, i64)> {
    let (
        event_id,
        sequence,
        position,
        timestamp,
        sensitivity,
        schema,
        causation,
        command,
        key,
        actor,
        payload,
        digest,
        correlation,
        aggregate,
        correlation_type,
        profile,
    ) = row;
    if schema != 1
        || correlation_type != CORRELATION_TYPE_CONVERSATION
        || profile != INTEGRITY_PROFILE_V2
        || aggregate.as_slice() != id.as_bytes()
        || correlation.as_slice() != id.as_bytes()
        || position <= 0
    {
        return Err(invalid());
    }
    let payload_value = ConversationEventCodec
        .decode(&payload)
        .map_err(|_| invalid())?;
    let sensitivity = stored_sensitivity(sensitivity).map_err(|_| invalid())?;
    if sensitivity != payload_value.sensitivity() {
        return Err(invalid());
    }
    let envelope = EventEnvelope::from_parts(
        parse_event_id(event_id).map_err(|_| invalid())?,
        AggregateId::Conversation(id),
        AggregateId::Conversation(id),
        causation
            .map(parse_event_id)
            .transpose()
            .map_err(|_| invalid())?,
        parse_command_id(command).map_err(|_| invalid())?,
        IdempotencyKey::new(String::from_utf8(key).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        u32::try_from(schema).map_err(|_| invalid())?,
        Actor::new(String::from_utf8(actor).map_err(|_| invalid())?).map_err(|_| invalid())?,
        sensitivity,
        payload_value,
        u64::try_from(sequence).map_err(|_| invalid())?,
        Timestamp::from_unix_micros(timestamp),
        parse_integrity_digest(digest).map_err(|_| invalid())?,
    );
    let expected = compute_integrity_digest_v2_with_global_position(&envelope, position, &payload)
        .map_err(|_| invalid())?;
    if expected != *envelope.integrity_digest() {
        return Err(invalid());
    }
    Ok((envelope, position))
}

pub(super) fn decode_taskrun(
    id: runne_domain::id::TaskRunId,
    row: RawRow,
) -> rusqlite::Result<(EventEnvelope<TaskRunEvent>, i64)> {
    let (
        event_id,
        sequence,
        position,
        timestamp,
        sensitivity,
        schema,
        causation,
        command,
        key,
        actor,
        payload_bytes,
        digest,
        correlation,
        aggregate,
        correlation_type,
        profile,
    ) = row;
    if schema != 1
        || correlation_type != CORRELATION_TYPE_TASK_RUN
        || profile != INTEGRITY_PROFILE_V1
        || aggregate.as_slice() != id.as_bytes()
        || correlation.as_slice() != id.as_bytes()
        || position <= 0
    {
        return Err(invalid());
    }
    let payload = TaskRunEventCodec
        .decode(&payload_bytes)
        .map_err(|_| invalid())?;
    let sensitivity = stored_sensitivity(sensitivity).map_err(|_| invalid())?;
    let submitted = matches!(&payload, TaskRunEvent::TaskRunSubmitted { .. });
    if (submitted && sensitivity != Sensitivity::Sensitive)
        || (!submitted && sensitivity != Sensitivity::Public)
    {
        return Err(invalid());
    }
    let envelope = EventEnvelope::from_parts(
        parse_event_id(event_id).map_err(|_| invalid())?,
        AggregateId::TaskRun(id),
        AggregateId::TaskRun(id),
        causation
            .map(parse_event_id)
            .transpose()
            .map_err(|_| invalid())?,
        parse_command_id(command).map_err(|_| invalid())?,
        IdempotencyKey::new(String::from_utf8(key).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        u32::try_from(schema).map_err(|_| invalid())?,
        Actor::new(String::from_utf8(actor).map_err(|_| invalid())?).map_err(|_| invalid())?,
        sensitivity,
        payload,
        u64::try_from(sequence).map_err(|_| invalid())?,
        Timestamp::from_unix_micros(timestamp),
        parse_integrity_digest(digest).map_err(|_| invalid())?,
    );
    let expected =
        compute_integrity_digest_with_global_position(&envelope, position, &payload_bytes)
            .map_err(|_| invalid())?;
    if expected != *envelope.integrity_digest() {
        return Err(invalid());
    }
    Ok((envelope, position))
}

pub(super) fn verify_head<E>(
    version: u64,
    last_event: Option<Vec<u8>>,
    last_timestamp: Option<i64>,
    events: &[EventEnvelope<E>],
    head: Option<(runne_domain::id::EventId, IntegrityDigest, i64, i64)>,
) -> rusqlite::Result<(runne_domain::id::EventId, IntegrityDigest, i64, i64)> {
    if events.len() as u64 != version
        || events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence() != index as u64 + 1)
    {
        return Err(invalid());
    }
    let head = head.ok_or_else(invalid)?;
    if last_event.as_deref() != Some(head.0.as_bytes().as_slice()) || last_timestamp != Some(head.3)
    {
        return Err(invalid());
    }
    if events.windows(2).any(|pair| {
        pair[0].timestamp() > pair[1].timestamp()
            || pair[1].causation_id() != Some(pair[0].event_id())
    }) {
        return Err(invalid());
    }
    if events
        .first()
        .is_none_or(|event| event.causation_id().is_some())
    {
        return Err(invalid());
    }
    Ok(head)
}

pub(super) fn verify_strict_position(previous: i64, current: i64) -> rusqlite::Result<()> {
    (current > previous).then_some(()).ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use runne_domain::{
        event::{Actor, EventEnvelope, Sensitivity},
        id::{AggregateId, CommandId, EventId, IdempotencyKey, IntegrityDigest, TaskRunId},
        task_run::TaskRunEvent,
        timestamp::Timestamp,
    };

    use super::{verify_head, verify_strict_position};

    fn event(sequence: u64, causation: Option<EventId>) -> EventEnvelope<TaskRunEvent> {
        let id = EventId::from_bytes([sequence as u8; 16]);
        let task_run = TaskRunId::from_bytes([9; 16]);
        EventEnvelope::from_parts(
            id,
            AggregateId::TaskRun(task_run),
            AggregateId::TaskRun(task_run),
            causation,
            CommandId::from_bytes([sequence as u8; 16]),
            IdempotencyKey::new(format!("snapshot-chain-{sequence}")).unwrap(),
            1,
            Actor::new("snapshot-test").unwrap(),
            Sensitivity::Public,
            TaskRunEvent::TaskRunCreated,
            sequence,
            Timestamp::from_unix_micros(sequence as i64),
            IntegrityDigest::from_bytes([0; 32]),
        )
    }

    #[test]
    fn canonical_causation_requires_none_then_immediate_predecessor() {
        let first = event(1, None);
        let second = event(2, Some(*first.event_id()));
        let third = event(3, Some(*second.event_id()));
        let head = Some((
            *third.event_id(),
            *third.integrity_digest(),
            3,
            third.timestamp().as_unix_micros(),
        ));
        assert!(
            verify_head(
                3,
                Some(third.event_id().as_bytes().to_vec()),
                Some(3),
                &[first.clone(), second.clone(), third],
                head
            )
            .is_ok()
        );

        let wrong_first = event(1, Some(EventId::from_bytes([7; 16])));
        assert!(
            verify_head(
                1,
                Some(wrong_first.event_id().as_bytes().to_vec()),
                Some(1),
                std::slice::from_ref(&wrong_first),
                Some((
                    *wrong_first.event_id(),
                    *wrong_first.integrity_digest(),
                    1,
                    1
                ))
            )
            .is_err()
        );
        for causation in [
            None,
            Some(EventId::from_bytes([2; 16])),
            Some(EventId::from_bytes([8; 16])),
        ] {
            let invalid_second = event(2, causation);
            assert!(
                verify_head(
                    2,
                    Some(invalid_second.event_id().as_bytes().to_vec()),
                    Some(2),
                    &[first.clone(), invalid_second.clone()],
                    Some((
                        *invalid_second.event_id(),
                        *invalid_second.integrity_digest(),
                        2,
                        2
                    ))
                )
                .is_err()
            );
        }
        for causation in [Some(*first.event_id()), Some(EventId::from_bytes([3; 16]))] {
            let invalid_third = event(3, causation);
            assert!(
                verify_head(
                    3,
                    Some(invalid_third.event_id().as_bytes().to_vec()),
                    Some(3),
                    &[first.clone(), second.clone(), invalid_third.clone()],
                    Some((
                        *invalid_third.event_id(),
                        *invalid_third.integrity_digest(),
                        3,
                        3,
                    ))
                )
                .is_err()
            );
        }
    }

    #[test]
    fn global_positions_must_strictly_increase_per_stream() {
        assert!(verify_strict_position(1, 2).is_ok());
        assert!(verify_strict_position(2, 2).is_err());
        assert!(verify_strict_position(2, 1).is_err());
    }
}
