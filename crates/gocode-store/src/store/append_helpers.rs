use super::event_guard::*;
use super::parse_helpers::*;
use super::*;

pub(super) fn append_conversation_event(
    transaction: &rusqlite::Transaction<'_>,
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<ConversationEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(), CommitError> {
    let (payload, digest, conversation_id) = guard_conversation_event(
        prohibited_content,
        event,
        sequence,
        global_position,
        timestamp,
    )?;
    insert_event(
        transaction,
        event,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V2,
    )
}

pub(super) fn append_guard_component(encoded: &mut Vec<u8>, component: &[u8]) {
    encoded.extend_from_slice(&(component.len() as u64).to_be_bytes());
    encoded.extend_from_slice(component);
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_event<E>(
    transaction: &rusqlite::Transaction<'_>,
    event: &UncommittedEvent<E>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
    integrity_profile: i64,
) -> Result<(), CommitError> {
    transaction
        .execute(
            "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position,
              timestamp, sensitivity, schema_version, causation_id, command_id,
              idempotency_key, actor, payload, integrity_digest, correlation_id,
              correlation_type, integrity_profile)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?3, ?2, ?15)",
            params![
                event.event_id().as_bytes(),
                aggregate_type,
                aggregate_id,
                sequence as i64,
                global_position,
                timestamp,
                sensitivity_value(*event.sensitivity()),
                event.schema_version() as i64,
                event.causation_id().map(EventId::as_bytes),
                event.command_id().as_bytes(),
                event.idempotency_key().as_str().as_bytes(),
                event.actor().as_str().as_bytes(),
                payload,
                digest.as_bytes(),
                integrity_profile,
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(())
}
