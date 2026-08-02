use super::append_helpers::*;
use super::component_guard::*;
use super::parse_helpers::*;
use super::*;

pub(super) fn guard_conversation_event(
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<ConversationEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(Vec<u8>, IntegrityDigest, ConversationId), CommitError> {
    let conversation_id = match event.aggregate_id() {
        AggregateId::Conversation(id) => *id,
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let payload = ConversationEventCodec
        .encode(event.payload())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let envelope = EventEnvelope::from_parts(
        *event.event_id(),
        AggregateId::Conversation(conversation_id),
        AggregateId::Conversation(conversation_id),
        event.causation_id().copied(),
        *event.command_id(),
        event.idempotency_key().clone(),
        event.schema_version(),
        event.actor().clone(),
        *event.sensitivity(),
        event.payload().clone(),
        sequence,
        Timestamp::from_unix_micros(timestamp),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_v2_with_global_position(&envelope, global_position, &payload)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    enforce_conversation_replay_size(
        event,
        conversation_id,
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
    )?;
    guard_event_components(
        prohibited_content,
        event,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V2,
    )?;
    Ok((payload, digest, conversation_id))
}

pub(super) fn append_taskrun_event(
    transaction: &rusqlite::Transaction<'_>,
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<TaskRunEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(), CommitError> {
    let (payload, digest, taskrun_id) = guard_taskrun_event(
        prohibited_content,
        event,
        sequence,
        global_position,
        timestamp,
    )?;
    insert_event(
        transaction,
        event,
        CORRELATION_TYPE_TASK_RUN,
        taskrun_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V1,
    )
}

pub(super) fn guard_taskrun_event(
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<TaskRunEvent>,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
) -> Result<(Vec<u8>, IntegrityDigest, TaskRunId), CommitError> {
    let taskrun_id = match event.aggregate_id() {
        AggregateId::TaskRun(id) => *id,
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let payload = TaskRunEventCodec
        .encode(event.payload())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let envelope = EventEnvelope::from_parts(
        *event.event_id(),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        event.causation_id().copied(),
        *event.command_id(),
        event.idempotency_key().clone(),
        event.schema_version(),
        event.actor().clone(),
        *event.sensitivity(),
        event.payload().clone(),
        sequence,
        Timestamp::from_unix_micros(timestamp),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    enforce_taskrun_replay_size(
        event,
        taskrun_id,
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
    )?;
    guard_event_components(
        prohibited_content,
        event,
        CORRELATION_TYPE_TASK_RUN,
        taskrun_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        &payload,
        digest,
        INTEGRITY_PROFILE_V1,
    )?;
    Ok((payload, digest, taskrun_id))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn enforce_conversation_replay_size(
    event: &UncommittedEvent<ConversationEvent>,
    conversation_id: ConversationId,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
) -> Result<(), CommitError> {
    let replay_event = replay_event_for_append(
        event,
        CORRELATION_TYPE_CONVERSATION,
        conversation_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        payload,
        digest,
        INTEGRITY_PROFILE_V2,
    )?;
    let actual = measured_conversation_replay_event_bytes(&replay_event, event.payload())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    validate_replay_writer_event_size(actual)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))
}
pub(super) fn enforce_taskrun_replay_size(
    event: &UncommittedEvent<TaskRunEvent>,
    taskrun_id: TaskRunId,
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
) -> Result<(), CommitError> {
    let replay_event = replay_event_for_append(
        event,
        CORRELATION_TYPE_TASK_RUN,
        taskrun_id.as_bytes(),
        sequence,
        global_position,
        timestamp,
        payload,
        digest,
        INTEGRITY_PROFILE_V1,
    )?;
    let actual = measured_taskrun_replay_event_bytes(&replay_event, event.payload())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    validate_replay_writer_event_size(actual)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay_event_for_append<E>(
    event: &UncommittedEvent<E>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
    integrity_profile: i64,
) -> Result<ReplayEvent, CommitError> {
    let aggregate_type = i32::try_from(aggregate_type)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let sequence = i64::try_from(sequence)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let correlation_type = match event.correlation_id() {
        AggregateId::TaskRun(_) => CORRELATION_TYPE_TASK_RUN,
        AggregateId::Conversation(_) => CORRELATION_TYPE_CONVERSATION,
        AggregateId::Workspace(_) => {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    };
    let correlation_id = match event.correlation_id() {
        AggregateId::TaskRun(id) => *id.as_bytes(),
        AggregateId::Conversation(id) => *id.as_bytes(),
        AggregateId::Workspace(_) => unreachable!("workspace correlation was rejected"),
    };
    Ok(ReplayEvent {
        global_position,
        event_id: *event.event_id().as_bytes(),
        aggregate_type,
        aggregate_id: *aggregate_id,
        payload: payload.to_vec(),
        timestamp,
        event_type: String::new(),
        sequence,
        sensitivity: i32::try_from(sensitivity_value(*event.sensitivity()))
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
        schema_version: event.schema_version(),
        causation_id: event.causation_id().map(|id| *id.as_bytes()),
        command_id: *event.command_id().as_bytes(),
        idempotency_key: event.idempotency_key().as_str().to_owned(),
        actor: event.actor().as_str().to_owned(),
        integrity_digest: *digest.as_bytes(),
        correlation_id,
        correlation_type: i32::try_from(correlation_type)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
        integrity_profile: i32::try_from(integrity_profile)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
    })
}
