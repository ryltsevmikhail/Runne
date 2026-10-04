use runne_application::ports::{TextGenerationPhase, TextGenerationReceipt};
use runne_application::provider::ProviderTerminalOutboxRecord;
use runne_domain::id::{AttemptId, MessageId, TaskRunId};
use runne_runtime::provider_execution::ProviderTerminalConversationResolveError;

pub(super) fn validate_identity(
    started: &TextGenerationReceipt,
    record: &ProviderTerminalOutboxRecord,
    message_id: MessageId,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> Result<(), ProviderTerminalConversationResolveError> {
    if started.conversation_id != record.conversation_id
        || started.taskrun_id != record.taskrun_id
        || started.attempt_id != record.execution_attempt_id
        || started.user_message_id != message_id
        || taskrun_id != record.taskrun_id
        || attempt_id != record.execution_attempt_id
        || !matches!(
            started.phase,
            TextGenerationPhase::Started
                | TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
        )
    {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    Ok(())
}

pub(super) fn validate_phase_version(
    started: &TextGenerationReceipt,
    begin_event_version: u64,
) -> Result<(), ProviderTerminalConversationResolveError> {
    let expected = match started.phase {
        TextGenerationPhase::Started => begin_event_version,
        TextGenerationPhase::Completed | TextGenerationPhase::Rejected => begin_event_version
            .checked_add(1)
            .ok_or(ProviderTerminalConversationResolveError::Conflict)?,
        TextGenerationPhase::ProhibitedInputRejected => {
            return Err(ProviderTerminalConversationResolveError::Conflict);
        }
    };
    if started.conversation_version != expected {
        return Err(ProviderTerminalConversationResolveError::Conflict);
    }
    Ok(())
}
