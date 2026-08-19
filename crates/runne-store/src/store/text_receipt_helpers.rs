use super::event_context::*;
use super::parse_helpers::*;
use super::*;

pub(super) fn lookup_text_receipt(
    connection: &Connection,
    command_id: CommandId,
    idempotency_key: &runne_domain::id::IdempotencyKey,
    scope: &[u8],
    fingerprint: &CommandFingerprint,
) -> Result<TextGenerationReceiptLookup, CommitError> {
    if let Some(stored_fingerprint) = connection
        .query_row(
            "SELECT semantic_fingerprint FROM project_workspace_command_receipts
             WHERE command_id = ?1",
            params![command_id.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_commit_read_error)?
    {
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: command_id,
            attempted_command_id: command_id,
            stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
            attempted_fingerprint: *fingerprint,
        });
    }
    let by_command = connection
        .query_row(
            "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
             FROM command_receipts WHERE command_id = ?1",
            params![command_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if let Some((stored_scope, stored_key, stored_fingerprint, stored_outcome)) = by_command {
        let stored_key = parse_idempotency_key_for_commit(stored_key)?;
        let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
        if stored_scope == scope
            && stored_key == *idempotency_key
            && stored_fingerprint == *fingerprint
        {
            let stored_result = TextGenerationReceiptCodec
                .decode(&stored_outcome)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            let stored_scope = IdempotencyScopeCodec
                .decode(&stored_scope)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
            let version_valid = match stored_result.phase {
                TextGenerationPhase::Started => stored_result.taskrun_version == 4,
                TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
                | TextGenerationPhase::ProhibitedInputRejected => {
                    stored_result.taskrun_version == 5
                }
            };
            if stored_scope.operation != OperationTag::GenerateConversationText || !version_valid {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
            crate::project_workspace::lineage::validate_text_taskrun_lineage(
                connection,
                stored_result.taskrun_id,
                stored_result.workspace_id,
                command_id,
                &stored_scope,
            )?;
            return Ok(TextGenerationReceiptLookup::Duplicate { stored_result });
        }
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: command_id,
            attempted_command_id: command_id,
            stored_fingerprint,
            attempted_fingerprint: *fingerprint,
        });
    }
    if let Some((stored_command, stored_fingerprint)) = connection
        .query_row(
            "SELECT command_id, fingerprint FROM command_receipts
             WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
            params![scope, idempotency_key.as_str().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
    {
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: parse_command_id_for_commit(stored_command)?,
            attempted_command_id: command_id,
            stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
            attempted_fingerprint: *fingerprint,
        });
    }
    Ok(TextGenerationReceiptLookup::Miss)
}

pub(super) fn validate_begin_text_payload(
    payload: &BeginTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 4
        || payload.receipt.phase != TextGenerationPhase::Started
        || payload.receipt.taskrun_version != 4
        || payload.receipt.conversation_version
            != payload.expected_conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_conversation_version,
                    event_count: 1,
                },
            )?
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let scope_matches = matches!(
        &payload.idempotency_scope,
        IdempotencyScope {
            runtime_authority_id,
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
            ..
        } if runtime_authority_id == authority
            && *conversation_id == payload.receipt.conversation_id
    );
    let conversation_event = &payload.conversation_events[0];
    let text = match conversation_event.payload() {
        ConversationEvent::UserMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } if *message_id == payload.receipt.user_message_id
            && *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id =>
        {
            text
        }
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let expected_fingerprint = CommandFingerprint::for_generate_conversation_text(
        &payload.receipt.conversation_id,
        payload.expected_conversation_version,
        text,
    );
    if !scope_matches
        || payload.command_fingerprint != expected_fingerprint
        || !valid_event_context(
            conversation_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(payload.receipt.conversation_id),
            Sensitivity::Sensitive,
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let expected_taskrun_payloads = [
        TaskRunEvent::TaskRunCreated,
        TaskRunEvent::TaskRunQueued,
        TaskRunEvent::TaskRunAdmitted,
        TaskRunEvent::AttemptStarted {
            attempt_id: payload.receipt.attempt_id,
        },
    ];
    for (index, (event, expected_payload)) in payload
        .taskrun_events
        .iter()
        .zip(expected_taskrun_payloads.iter())
        .enumerate()
    {
        if event.payload() != expected_payload
            || !valid_event_context(
                event,
                payload.command_id,
                &payload.idempotency_key,
                AggregateId::TaskRun(payload.receipt.taskrun_id),
                Sensitivity::Public,
            )
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let expected_causation = index
            .checked_sub(1)
            .map(|previous| *payload.taskrun_events[previous].event_id());
        if event.causation_id().copied() != expected_causation {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    Ok(())
}
