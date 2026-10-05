use super::*;

pub(super) fn validate_input(
    store: &StoreTransaction,
    input: &D2ToolLoopFailureV1,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    use crate::store::test_support_diagnostics as diagnostics;
    use runne_application::ports::TextGenerationPhase;
    let invalid = input.taskrun_id != input.assignment.taskrun_id
        || !matches!(
            input.reason,
            runne_domain::conversation::GenerationFailureReason::ProviderExecutionRejected
                | runne_domain::conversation::GenerationFailureReason::InterruptedByRestart
        )
        || input.attempt_id != input.assignment.attempt_id
        || input.started_receipt.phase != TextGenerationPhase::Started
        || input.started_receipt.taskrun_id != input.taskrun_id
        || input.started_receipt.attempt_id != input.attempt_id
        || input.started_receipt.conversation_id != input.conversation_id
        || input.failed_receipt.phase != TextGenerationPhase::Rejected
        || input.failed_receipt.taskrun_id != input.taskrun_id
        || input.failed_receipt.attempt_id != input.attempt_id
        || input.failed_receipt.conversation_id != input.conversation_id
        || input.failed_receipt.workspace_id != input.started_receipt.workspace_id
        || input.failed_receipt.user_message_id != input.started_receipt.user_message_id
        || input.failed_receipt.assistant_message_id != input.started_receipt.assistant_message_id
        || input
            .expected_conversation_version
            .checked_add(1)
            .is_none_or(|version| input.failed_receipt.conversation_version != version)
        || input.failed_receipt.taskrun_version != input.expected_taskrun_head
        || input.idempotency_scope.runtime_authority_id != *store.runtime_authority_id()
        || input.idempotency_scope.operation != OperationTag::GenerateConversationText
        || input.idempotency_scope.aggregate_scope
            != (AggregateScope::ExistingConversation {
                conversation_id: input.conversation_id,
            })
        || input.conversation_event.command_id() != &input.command_id
        || input.conversation_event.idempotency_key() != &input.idempotency_key
        || input.conversation_event.actor() != &input.actor
        || input.conversation_event.sensitivity()
            != &input.conversation_event.payload().sensitivity()
        || input.conversation_event.aggregate_id()
            != &AggregateId::Conversation(input.conversation_id)
        || !matches!(input.conversation_event.payload(), ConversationEvent::GenerationFailed {
            taskrun_id, attempt_id, reason
        } if *taskrun_id == input.taskrun_id && *attempt_id == input.attempt_id && *reason == input.reason);
    if invalid {
        diagnostics::record("failure.input_binding");
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
