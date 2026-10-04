fn taskrun_event_type(event: &TaskRunEvent) -> &'static str {
    match event {
        TaskRunEvent::TaskRunSubmitted { .. } => "TaskRunSubmitted",
        TaskRunEvent::TaskRunCreated => "TaskRunCreated",
        TaskRunEvent::TaskRunQueued => "TaskRunQueued",
        TaskRunEvent::TaskRunAdmitted => "TaskRunAdmitted",
        TaskRunEvent::AttemptStarted { .. } => "AttemptStarted",
        TaskRunEvent::WaitStarted => "WaitStarted",
        TaskRunEvent::Resumed => "Resumed",
        TaskRunEvent::RetryStarted { .. } => "RetryStarted",
        TaskRunEvent::RetryCompleted { .. } => "RetryCompleted",
        TaskRunEvent::CheckpointStarted => "CheckpointStarted",
        TaskRunEvent::CheckpointCommitted => "CheckpointCommitted",
        TaskRunEvent::CancellationRequested => "CancellationRequested",
        TaskRunEvent::CancellationCompleted => "CancellationCompleted",
        TaskRunEvent::TaskRunCompleted { .. } => "TaskRunCompleted",
        TaskRunEvent::TaskRunFailed { .. } => "TaskRunFailed",
        TaskRunEvent::BudgetExhausted => "BudgetExhausted",
        TaskRunEvent::PolicyDenied => "PolicyDenied",
        TaskRunEvent::ReconciliationStarted => "ReconciliationStarted",
        TaskRunEvent::Reconciled => "Reconciled",
        TaskRunEvent::Unrecoverable => "Unrecoverable",
        TaskRunEvent::UserSupersedeUnknown { .. } => "UserSupersedeUnknown",
        TaskRunEvent::TaskRunCancelled => "TaskRunCancelled",
        TaskRunEvent::LoopCycleStarted { .. } => "LoopCycleStarted",
        TaskRunEvent::ContextCommitted { .. } => "ContextCommitted",
        TaskRunEvent::PlanCommitted { .. } => "PlanCommitted",
        TaskRunEvent::StepOutcomeRecorded { .. } => "StepOutcomeRecorded",
        TaskRunEvent::LoopCycleCompleted { .. } => "LoopCycleCompleted",
        TaskRunEvent::NextCycleCreated { .. } => "NextCycleCreated",
        TaskRunEvent::RetryScheduled { .. } => "RetryScheduled",
        TaskRunEvent::ActivateScheduledRetryAttempt { .. } => "ActivateScheduledRetryAttempt",
        TaskRunEvent::RecoveryResumeStarted { .. } => "RecoveryResumeStarted",
        TaskRunEvent::LoopCheckpointStarted { .. } => "LoopCheckpointStarted",
        TaskRunEvent::LoopCheckpointRecorded { .. } => "LoopCheckpointRecorded",
        TaskRunEvent::LoopCheckpointCommitted { .. } => "LoopCheckpointCommitted",
        TaskRunEvent::LoopWakeAccepted { .. } => "LoopWakeAccepted",
    }
}

fn conversation_event_type(event: &ConversationEvent) -> &'static str {
    match event {
        ConversationEvent::ConversationCreated { .. } => "ConversationCreated",
        ConversationEvent::UserMessageAppended { .. } => "UserMessageAppended",
        ConversationEvent::AssistantMessageAppended { .. } => "AssistantMessageAppended",
        ConversationEvent::GenerationFailed { .. } => "GenerationFailed",
        ConversationEvent::GenerationSupersededUnknown { .. } => "GenerationSupersededUnknown",
        ConversationEvent::ConversationClosed => "ConversationClosed",
    }
}

fn validated_event_id(bytes: [u8; 16], index: usize) -> rusqlite::Result<EventId> {
    let id = EventId::from_bytes(bytes);
    id.to_string()
        .parse()
        .map_err(|_| invalid_column(index, rusqlite::types::Type::Blob))
}

fn validated_command_id(bytes: [u8; 16], index: usize) -> rusqlite::Result<CommandId> {
    let id = CommandId::from_bytes(bytes);
    id.to_string()
        .parse()
        .map_err(|_| invalid_column(index, rusqlite::types::Type::Blob))
}

fn validate_replay_event_integrity(event: &ReplayEvent) -> rusqlite::Result<(String, usize)> {
    let sequence = u64::try_from(event.sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| invalid_column(3, rusqlite::types::Type::Integer))?;
    if event.global_position <= 0 {
        return Err(invalid_column(4, rusqlite::types::Type::Integer));
    }
    if event.schema_version == 0 {
        return Err(invalid_column(7, rusqlite::types::Type::Integer));
    }
    let event_id = validated_event_id(event.event_id, 0)?;
    let causation_id = event
        .causation_id
        .map(|id| validated_event_id(id, 8))
        .transpose()?;
    let command_id = validated_command_id(event.command_id, 9)?;
    let idempotency_key = IdempotencyKey::new(event.idempotency_key.clone())
        .map_err(|_| invalid_column(10, rusqlite::types::Type::Blob))?;
    if event
        .actor
        .as_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return Err(invalid_column(11, rusqlite::types::Type::Blob));
    }
    let actor = Actor::new(event.actor.clone())
        .map_err(|_| invalid_column(11, rusqlite::types::Type::Blob))?;
    let sensitivity = match event.sensitivity {
        0 => Sensitivity::Public,
        1 => Sensitivity::Internal,
        2 => Sensitivity::Sensitive,
        _ => return Err(invalid_column(6, rusqlite::types::Type::Integer)),
    };
    let integrity_digest = IntegrityDigest::from_bytes(event.integrity_digest);
    let timestamp = Timestamp::from_unix_micros(event.timestamp);

    match event.aggregate_type {
        1 => {
            if event.correlation_type != 1
                || event.integrity_profile != 1
                || event.correlation_id != event.aggregate_id
            {
                return Err(invalid_column(15, rusqlite::types::Type::Integer));
            }
            let taskrun_id = TaskRunId::from_bytes(event.aggregate_id);
            let taskrun_id: TaskRunId = taskrun_id
                .to_string()
                .parse()
                .map_err(|_| invalid_column(2, rusqlite::types::Type::Blob))?;
            let payload = TaskRunEventCodec
                .decode(&event.payload)
                .map_err(|_| invalid_column(12, rusqlite::types::Type::Blob))?;
            let expected_sensitivity = match &payload {
                runne_domain::task_run::TaskRunEvent::TaskRunSubmitted { .. } => {
                    Sensitivity::Sensitive
                }
                _ => Sensitivity::Public,
            };
            if sensitivity != expected_sensitivity {
                return Err(invalid_column(6, rusqlite::types::Type::Integer));
            }
            let event_type = taskrun_event_type(&payload).to_owned();
            let encoded_size = measured_taskrun_replay_event_bytes(event, &payload)
                .map_err(|_| invalid_column(12, rusqlite::types::Type::Blob))?;
            let envelope = EventEnvelope::from_parts(
                event_id,
                AggregateId::TaskRun(taskrun_id),
                AggregateId::TaskRun(taskrun_id),
                causation_id,
                command_id,
                idempotency_key,
                event.schema_version,
                actor,
                sensitivity,
                payload,
                sequence,
                timestamp,
                integrity_digest,
            );
            let expected = compute_integrity_digest_with_global_position(
                &envelope,
                event.global_position,
                &event.payload,
            )
            .map_err(|_| invalid_column(13, rusqlite::types::Type::Blob))?;
            if expected.as_bytes() != &event.integrity_digest {
                return Err(invalid_column(13, rusqlite::types::Type::Blob));
            }
            Ok((event_type, encoded_size))
        }
        2 => {
            if event.correlation_type != 2
                || event.integrity_profile != 2
                || event.correlation_id != event.aggregate_id
            {
                return Err(invalid_column(15, rusqlite::types::Type::Integer));
            }
            let conversation_id = ConversationId::from_bytes(event.aggregate_id);
            let conversation_id: ConversationId = conversation_id
                .to_string()
                .parse()
                .map_err(|_| invalid_column(2, rusqlite::types::Type::Blob))?;
            let payload = ConversationEventCodec
                .decode(&event.payload)
                .map_err(|_| invalid_column(12, rusqlite::types::Type::Blob))?;
            if payload.sensitivity() != sensitivity {
                return Err(invalid_column(6, rusqlite::types::Type::Integer));
            }
            let event_type = conversation_event_type(&payload).to_owned();
            let encoded_size = measured_conversation_replay_event_bytes(event, &payload)
                .map_err(|_| invalid_column(12, rusqlite::types::Type::Blob))?;
            let envelope = EventEnvelope::from_parts(
                event_id,
                AggregateId::Conversation(conversation_id),
                AggregateId::Conversation(conversation_id),
                causation_id,
                command_id,
                idempotency_key,
                event.schema_version,
                actor,
                sensitivity,
                payload,
                sequence,
                timestamp,
                integrity_digest,
            );
            let expected = compute_integrity_digest_v2_with_global_position(
                &envelope,
                event.global_position,
                &event.payload,
            )
            .map_err(|_| invalid_column(13, rusqlite::types::Type::Blob))?;
            if expected.as_bytes() != &event.integrity_digest {
                return Err(invalid_column(13, rusqlite::types::Type::Blob));
            }
            Ok((event_type, encoded_size))
        }
        _ => Err(invalid_column(1, rusqlite::types::Type::Integer)),
    }
}

/// Read a [`ReplayEvent`] from a rusqlite row.
///
/// Column layout: 0=event_id, 1=aggregate_type, 2=aggregate_id,
/// 3=sequence, 4=global_position, 5=timestamp, 6=sensitivity,
/// 7=schema_version, 12=payload, 14=correlation_id, 15=correlation_type.
fn read_replay_event(row: &rusqlite::Row) -> rusqlite::Result<ReplayEvent> {
    let event_id = fixed_blob(row.get(0)?, 0)?;
    let aggregate_type: i32 = row.get(1)?;
    let aggregate_id = fixed_blob(row.get(2)?, 2)?;
    let sequence: i64 = row.get(3)?;
    let global_position: i64 = row.get(4)?;
    let timestamp: i64 = row.get(5)?;
    let sensitivity: i32 = row.get(6)?;
    if !matches!(sensitivity, 0..=2) {
        return Err(invalid_column(6, rusqlite::types::Type::Integer));
    }
    let schema_version: u32 = row.get(7)?;
    let causation_id = optional_event_id(row.get(8)?, 8)?;
    let command_id = fixed_blob(row.get(9)?, 9)?;
    let idempotency_key = String::from_utf8(row.get(10)?)
        .ok()
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or_else(|| invalid_column(10, rusqlite::types::Type::Blob))?;
    let actor = String::from_utf8(row.get(11)?)
        .ok()
        .and_then(|value| Actor::new(value).ok())
        .ok_or_else(|| invalid_column(11, rusqlite::types::Type::Blob))?;
    let payload: Vec<u8> = row.get(12)?;
    let integrity_digest = fixed_blob(row.get(13)?, 13)?;
    let correlation_id = fixed_blob(row.get(14)?, 14)?;
    let correlation_type: i32 = row.get(15)?;
    if !matches!(correlation_type, 1 | 2) {
        return Err(invalid_column(15, rusqlite::types::Type::Integer));
    }
    let integrity_profile: i32 = row.get(16)?;
    if !matches!(integrity_profile, 1 | 2) {
        return Err(invalid_column(16, rusqlite::types::Type::Integer));
    }
    let mut event = ReplayEvent {
        global_position,
        event_id,
        aggregate_type,
        aggregate_id,
        payload,
        timestamp,
        event_type: String::new(),
        sequence,
        sensitivity,
        schema_version,
        causation_id,
        command_id,
        idempotency_key: idempotency_key.as_str().to_owned(),
        actor: actor.as_str().to_owned(),
        integrity_digest,
        correlation_id,
        correlation_type,
        integrity_profile,
    };
    event.event_type = validate_replay_event_integrity(&event)?.0;
    Ok(event)
}
