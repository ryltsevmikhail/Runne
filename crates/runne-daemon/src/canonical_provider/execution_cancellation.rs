use super::*;

pub(crate) fn foreground_cancellation_result(
    store: &StoreTransaction,
    taskrun_id: runne_domain::id::TaskRunId,
    conversation_id: runne_domain::id::ConversationId,
    attempt_id: runne_domain::id::AttemptId,
    command_id: runne_domain::id::CommandId,
    idempotency_key: &runne_domain::id::IdempotencyKey,
) -> Result<Option<runne_application::ports::TextGenerationReceipt>, CanonicalProviderExecutionError>
{
    use runne_application::ports::{EventStore, TextGenerationPhase};
    let taskrun = store
        .load_task_run(taskrun_id)
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    let state = runne_domain::task_run::TaskRun::replay(&taskrun.events)
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?
        .state();
    if state == runne_domain::task_run::TaskRunState::Cancelling {
        // Leave the sealed terminal evidence for the independent cancellation
        // scanner; the foreground future never owns cancellation settlement.
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    if state != runne_domain::task_run::TaskRunState::Cancelled {
        return Ok(None);
    }
    let conversation = store
        .load_conversation(conversation_id)
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    if !conversation.events.iter().any(|event| matches!(event.payload(),
        ConversationEvent::GenerationFailed { taskrun_id: failed_taskrun, attempt_id: failed_attempt,
            reason: runne_domain::conversation::GenerationFailureReason::Cancelled }
            if *failed_taskrun == taskrun_id && *failed_attempt == attempt_id)) {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    let receipt = store
        .load_text_generation_receipt_by_command(command_id, idempotency_key)
        .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    if receipt.phase != TextGenerationPhase::Rejected
        || receipt.taskrun_id != taskrun_id
        || receipt.conversation_id != conversation_id
        || receipt.attempt_id != attempt_id
    {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    Ok(Some(receipt))
}
