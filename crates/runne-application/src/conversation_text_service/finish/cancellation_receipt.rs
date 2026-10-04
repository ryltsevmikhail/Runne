fn validate_terminal_cancellation_receipt(
    receipt: &TextGenerationReceipt,
    conversation_id: runne_domain::id::ConversationId,
) -> Result<(), ConversationTextServiceError> {
    if receipt.phase == TextGenerationPhase::Rejected && receipt.taskrun_version == 6 {
        if receipt.conversation_id == conversation_id {
            return Ok(());
        }
        return Err(ConversationTextServiceError::ReceiptMismatch);
    }
    validate_receipt(receipt, conversation_id)
}

fn validate_no_admission_replay<R: crate::ports::ConversationTextRepository>(
    repository: &R,
    receipt: &TextGenerationReceipt,
    completion: &ConversationTextCompletion,
) -> Result<(), ConversationTextServiceError> {
    let ConversationTextCompletion::NoProviderAdmissionCancellation { evidence } = completion
    else {
        return Ok(());
    };
    if receipt.phase != TextGenerationPhase::Rejected || receipt.taskrun_version != 6 {
        return Ok(());
    }
    if evidence.cancellation_taskrun_version.checked_add(1) != Some(receipt.taskrun_version)
        || !repository
            .validate_no_admission_cancellation_receipt(receipt)
            .map_err(map_commit)?
    {
        return Err(ConversationTextServiceError::ReceiptMismatch);
    }
    Ok(())
}

fn commit_terminal_cancellation_result(
    result: TextGenerationCommitResult,
    conversation_id: runne_domain::id::ConversationId,
) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
    let receipt = match result {
        TextGenerationCommitResult::Committed { result } => result,
        TextGenerationCommitResult::Duplicate { stored_result } => stored_result,
    };
    validate_terminal_cancellation_receipt(&receipt, conversation_id)?;
    Ok(receipt)
}
