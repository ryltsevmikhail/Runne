use super::event_context::*;
use super::parse_helpers::*;
use super::*;

pub(super) fn validate_finish_text_payload(
    payload: &FinishTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 1
        || payload.receipt.phase != TextGenerationPhase::Completed
        || payload.receipt.conversation_version
            != payload.expected_conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_conversation_version,
                    event_count: 1,
                },
            )?
        || payload.receipt.taskrun_version
            != payload.expected_taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_taskrun_version,
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
    let message_matches = matches!(
        conversation_event.payload(),
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            ..
        } if *message_id == payload.receipt.assistant_message_id
            && *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id
    );
    let taskrun_event = &payload.taskrun_events[0];
    if !scope_matches
        || !message_matches
        || !matches!(
            taskrun_event.payload(),
            TaskRunEvent::TaskRunCompleted {
                result: runne_domain::command::TerminalResult::Success
            }
        )
        || !valid_event_context(
            conversation_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(payload.receipt.conversation_id),
            Sensitivity::Sensitive,
        )
        || !valid_event_context(
            taskrun_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::TaskRun(payload.receipt.taskrun_id),
            Sensitivity::Public,
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn validate_reject_text_payload(
    payload: &RejectTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 1
        || !matches!(
            payload.receipt.phase,
            TextGenerationPhase::Rejected | TextGenerationPhase::ProhibitedInputRejected
        )
        || payload.receipt.conversation_version
            != payload.expected_conversation_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_conversation_version,
                    event_count: 1,
                },
            )?
        || payload.receipt.taskrun_version
            != payload.expected_taskrun_version.checked_add(1).ok_or(
                CommitError::VersionExhausted {
                    current: payload.expected_taskrun_version,
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
    let rejection_reason = match conversation_event.payload() {
        ConversationEvent::GenerationFailed {
            taskrun_id,
            attempt_id,
            reason,
        } if *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id =>
        {
            Some(*reason)
        }
        _ => None,
    };
    let taskrun_event = &payload.taskrun_events[0];
    if !scope_matches
        || rejection_reason.is_none()
        || rejection_reason == Some(runne_domain::conversation::GenerationFailureReason::Cancelled)
        || !matches!(
            taskrun_event.payload(),
            TaskRunEvent::TaskRunFailed { reason }
                if rejection_reason.is_some_and(|closed| *reason == closed.as_code())
        )
        || !valid_event_context(
            conversation_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(payload.receipt.conversation_id),
            Sensitivity::Public,
        )
        || !valid_event_context(
            taskrun_event,
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::TaskRun(payload.receipt.taskrun_id),
            Sensitivity::Public,
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
