struct TerminalCancellationOptions {
    remote_artifact: Option<crate::ports::ProviderRemoteArtifactCancellationEvidence>,
    d2_tool_loop: Option<crate::ports::D2ToolLoopCancellationEvidence>,
    terminal: Option<crate::ports::ProviderTerminalCancellationEvidence>,
    unknown_terminal: Option<crate::ports::ProviderUnknownTerminalCancellationEvidence>,
    pre_effect: Option<crate::ports::ProviderPreEffectCancellationEvidence>,
    no_admission: Option<crate::ports::ProviderNoAdmissionCancellationEvidence>,
    d2_restart: Option<crate::ports::D2ToolLoopRestartEvidence>,
}

fn finish_result<R: ConversationTextRepository>(
    repository: &R,
    result: TextGenerationCommitResult,
    conversation_id: runne_domain::id::ConversationId,
    options: TerminalCancellationOptions,
) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
    if options.remote_artifact.is_some() {
        let receipt = match result {
            TextGenerationCommitResult::Committed { result } => result,
            TextGenerationCommitResult::Duplicate { stored_result } => stored_result,
        };
        if receipt.phase != TextGenerationPhase::Rejected || receipt.conversation_id != conversation_id
        {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        Ok(receipt)
    } else if let Some(evidence) = options.d2_restart {
        let receipt = match result {
            TextGenerationCommitResult::Committed { result }
            | TextGenerationCommitResult::Duplicate {
                stored_result: result,
            } => result,
        };
        validate_d2_tool_loop_restart_receipt(&receipt, conversation_id, &evidence)?;
        Ok(receipt)
    } else if let Some(evidence) = options.d2_tool_loop {
        let receipt = match result {
            TextGenerationCommitResult::Committed { result }
            | TextGenerationCommitResult::Duplicate {
                stored_result: result,
            } => result,
        };
        if receipt.phase != TextGenerationPhase::Rejected
            || receipt.conversation_id != conversation_id
            || evidence.cancellation_taskrun_version.checked_add(1) != Some(receipt.taskrun_version)
            || !repository
                .validate_d2_tool_loop_cancellation_receipt(&receipt, evidence)
                .map_err(map_commit)?
        {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        Ok(receipt)
    } else if options.terminal.is_some()
        || options.unknown_terminal.is_some()
        || options.pre_effect.is_some()
        || options.no_admission.is_some()
        || options.d2_tool_loop.is_some()
    {
        commit_terminal_cancellation_result(result, conversation_id)
    } else {
        commit_result(result, conversation_id)
    }
}

fn validate_d2_tool_loop_restart_receipt(
    receipt: &TextGenerationReceipt,
    conversation_id: runne_domain::id::ConversationId,
    evidence: &crate::ports::D2ToolLoopRestartEvidence,
) -> Result<(), ConversationTextServiceError> {
    if receipt.phase != TextGenerationPhase::Rejected
        || receipt.conversation_id != conversation_id
        || evidence.expected_taskrun_head.checked_add(1) != Some(receipt.taskrun_version)
    {
        return Err(ConversationTextServiceError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_d2_tool_loop_restart_replay(
    receipt: &TextGenerationReceipt,
    completion: &crate::commands::ConversationTextCompletion,
    conversation_id: runne_domain::id::ConversationId,
) -> Result<(), ConversationTextServiceError> {
    match completion {
        crate::commands::ConversationTextCompletion::D2ToolLoopRestart { evidence }
            if receipt.phase == TextGenerationPhase::Rejected =>
        {
            validate_d2_tool_loop_restart_receipt(receipt, conversation_id, evidence)
        }
        crate::commands::ConversationTextCompletion::D2ToolLoopRestart { .. } => {
            validate_receipt(receipt, conversation_id)
        }
        _ => Ok(()),
    }
}
