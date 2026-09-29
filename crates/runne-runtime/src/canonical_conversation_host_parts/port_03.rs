
fn into_application_context(
    context: ConversationCommandContext,
) -> Result<ApplicationCommandContext, ConversationHostError> {
    let actor = Actor::new(context.actor.as_str().to_owned())
        .map_err(|_| ConversationHostError::InvariantViolation)?;
    Ok(ApplicationCommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key,
        principal_id: PrincipalId(context.principal.as_str().to_owned()),
        actor,
    })
}

fn event_to_message(
    event: &runne_domain::event::EventEnvelope<ConversationEvent>,
) -> Option<Result<CanonicalConversationMessage, ConversationHostError>> {
    let (message_id, role, taskrun_id, attempt_id, text) = match event.payload() {
        ConversationEvent::UserMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } => (
            *message_id,
            CanonicalMessageRole::User,
            *taskrun_id,
            *attempt_id,
            text.as_str(),
        ),
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } => (
            *message_id,
            CanonicalMessageRole::Assistant,
            *taskrun_id,
            *attempt_id,
            text.as_str(),
        ),
        ConversationEvent::ConversationCreated { .. } | ConversationEvent::ConversationClosed => {
            return None;
        }
        ConversationEvent::GenerationFailed { .. } => return None,
    };
    let committed_at =
        NonNegativeUnixMillis::new(event.timestamp().as_unix_micros().div_euclid(1_000))
            .ok_or(ConversationHostError::Unavailable);
    Some(
        committed_at.map(|committed_at| CanonicalConversationMessage {
            message_id,
            role,
            taskrun_id,
            attempt_id,
            text: text.to_owned(),
            committed_at,
        }),
    )
}

fn result_from_snapshot(
    receipt: TextGenerationReceipt,
    snapshot: ConversationMessagesSnapshot,
) -> Result<ConversationTextResult, ConversationHostError> {
    if snapshot.stream_version != receipt.conversation_version {
        return Err(ConversationHostError::InvariantViolation);
    }
    let user_message = snapshot
        .messages
        .iter()
        .find(|message| message.message_id == receipt.user_message_id)
        .cloned()
        .ok_or(ConversationHostError::InvariantViolation)?;
    let assistant_message = snapshot
        .messages
        .iter()
        .find(|message| message.message_id == receipt.assistant_message_id)
        .cloned()
        .ok_or(ConversationHostError::InvariantViolation)?;
    if user_message.role != CanonicalMessageRole::User
        || assistant_message.role != CanonicalMessageRole::Assistant
        || user_message.taskrun_id != receipt.taskrun_id
        || assistant_message.taskrun_id != receipt.taskrun_id
        || user_message.attempt_id != receipt.attempt_id
        || assistant_message.attempt_id != receipt.attempt_id
    {
        return Err(ConversationHostError::InvariantViolation);
    }

    Ok(ConversationTextResult {
        conversation_id: receipt.conversation_id,
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        conversation_stream_version: receipt.conversation_version,
        taskrun_stream_version: receipt.taskrun_version,
        user_message,
        assistant_message,
    })
}

fn validate_loaded_stream(
    stream: &runne_application::ports::ConversationLoadedStream,
) -> Result<(), ConversationHostError> {
    let Some(last) = stream.events.last() else {
        return Err(ConversationHostError::Unavailable);
    };
    if stream.current_version != last.sequence()
        || stream.last_event_id != Some(*last.event_id())
        || stream.events.len() as u64 != stream.current_version
    {
        return Err(ConversationHostError::Unavailable);
    }
    Ok(())
}

fn map_create_error(error: ConversationServiceError) -> ConversationHostError {
    match error {
        ConversationServiceError::Commit(CommitError::VersionConflict { .. })
        | ConversationServiceError::Commit(CommitError::IdempotencyConflict { .. }) => {
            ConversationHostError::Conflict
        }
        ConversationServiceError::Commit(_)
        | ConversationServiceError::IdGeneration(_)
        | ConversationServiceError::InvalidCommitTimestamp => ConversationHostError::Unavailable,
        ConversationServiceError::InvalidActor
        | ConversationServiceError::ContextMismatch
        | ConversationServiceError::MaterializationFailed
        | ConversationServiceError::ReceiptMismatch => ConversationHostError::InvariantViolation,
    }
}

fn map_runtime_error(error: RuntimeError) -> ConversationHostError {
    match error {
        RuntimeError::Backpressure { .. } => ConversationHostError::Backpressure,
        RuntimeError::RuntimeClosed | RuntimeError::WorkerExecutionFailed { .. } => {
            ConversationHostError::Unavailable
        }
        RuntimeError::Application(_) => ConversationHostError::InvariantViolation,
        RuntimeError::ConversationApplication(error) => match error {
            ConversationTextServiceError::ProhibitedSecretMaterial => {
                ConversationHostError::ProhibitedSecretMaterial
            }
            ConversationTextServiceError::ConversationNotFound => ConversationHostError::NotFound,
            ConversationTextServiceError::WriterFenced => {
                ConversationHostError::WriterFenced
            }
            ConversationTextServiceError::Conflict
            | ConversationTextServiceError::ConversationDomain(_) => {
                ConversationHostError::Conflict
            }
            ConversationTextServiceError::StoredDataUnavailable
            | ConversationTextServiceError::IdGeneration(_)
            | ConversationTextServiceError::Commit(_) => ConversationHostError::Unavailable,
            ConversationTextServiceError::TaskRunDomain
            | ConversationTextServiceError::MaterializationFailed
            | ConversationTextServiceError::ReceiptMismatch => {
                ConversationHostError::InvariantViolation
            }
        },
    }
}

fn map_event_store_error(error: EventStoreError) -> ConversationHostError {
    match error {
        EventStoreError::NotFound => ConversationHostError::NotFound,
        EventStoreError::CorruptData | EventStoreError::Unavailable => {
            ConversationHostError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_provider_is_stable_and_keeps_large_output_bounded() {
        let provider = DeterministicTextProvider;
        assert_eq!(
            provider
                .generate(&MessageText::new("hello").unwrap())
                .unwrap(),
            MessageText::new("Runne local response: hello").unwrap()
        );

        let maximum = MessageText::new("x".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap();
        let first = provider.generate(&maximum).unwrap();
        let second = provider.generate(&maximum).unwrap();
        assert_eq!(first, second);
        assert!(first.as_str().len() <= MAX_MESSAGE_TEXT_BYTES);
        assert!(first.as_str().starts_with(LOCAL_RESPONSE_PREFIX));
    }

    #[test]
    fn only_proven_pre_effect_provider_failure_may_reject_started_generation() {
        assert!(provider_error_is_proven_pre_effect(
            CanonicalProviderExecutionError::RejectedBeforeEffect
        ));
        for error in [
            CanonicalProviderExecutionError::RemoteFailed,
            CanonicalProviderExecutionError::RemoteIncomplete,
            CanonicalProviderExecutionError::Uncertain,
            CanonicalProviderExecutionError::PolicyDenied,
            CanonicalProviderExecutionError::Unavailable,
            CanonicalProviderExecutionError::Conflict,
        ] {
            assert!(!provider_error_is_proven_pre_effect(error));
        }
    }
}
