fn domain_context(context: &ApplicationCommandContext) -> CommandContext {
    CommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        actor: context.actor.clone(),
    }
}

fn validate_conversation_stream(
    stream: &crate::ports::ConversationLoadedStream,
) -> Result<(), ConversationTextServiceError> {
    let Some(last) = stream.events.last() else {
        return Err(ConversationTextServiceError::StoredDataUnavailable);
    };
    if stream.current_version != last.sequence()
        || stream.last_event_id != Some(*last.event_id())
        || stream.events.len() as u64 != stream.current_version
    {
        return Err(ConversationTextServiceError::StoredDataUnavailable);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &TextGenerationReceipt,
    conversation_id: gocode_domain::id::ConversationId,
) -> Result<(), ConversationTextServiceError> {
    let versions_valid = match receipt.phase {
        TextGenerationPhase::Started => receipt.taskrun_version == 4,
        TextGenerationPhase::Completed
        | TextGenerationPhase::Rejected
        | TextGenerationPhase::ProhibitedInputRejected => receipt.taskrun_version == 5,
    };
    if receipt.conversation_id != conversation_id || !versions_valid {
        return Err(ConversationTextServiceError::ReceiptMismatch);
    }
    Ok(())
}

fn commit_result(
    result: TextGenerationCommitResult,
    conversation_id: gocode_domain::id::ConversationId,
) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
    let result = match result {
        TextGenerationCommitResult::Committed { result } => result,
        TextGenerationCommitResult::Duplicate { stored_result } => stored_result,
    };
    validate_receipt(&result, conversation_id)?;
    Ok(result)
}

fn map_conversation_load(error: EventStoreError) -> ConversationTextServiceError {
    match error {
        EventStoreError::NotFound => ConversationTextServiceError::ConversationNotFound,
        EventStoreError::CorruptData | EventStoreError::Unavailable => {
            ConversationTextServiceError::StoredDataUnavailable
        }
    }
}

fn map_commit(error: CommitError) -> ConversationTextServiceError {
    match error {
        CommitError::VersionConflict { .. } | CommitError::IdempotencyConflict { .. } => {
            ConversationTextServiceError::Conflict
        }
        error => ConversationTextServiceError::Commit(error),
    }
}
