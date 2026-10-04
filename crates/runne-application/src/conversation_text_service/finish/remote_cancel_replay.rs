impl<R, I> ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore,
    I: IdGenerator,
{
    fn replay_remote_artifact_cancellation(
        &self,
        context: &ApplicationCommandContext,
        input: &FinishConversationTextInput,
        durable: &TextGenerationReceipt,
        scope: &IdempotencyScope,
        fingerprint: &CommandFingerprint,
    ) -> Result<Option<TextGenerationReceipt>, ConversationTextServiceError> {
        if durable.phase != TextGenerationPhase::Rejected {
            return Ok(None);
        }
        let evidence = match &input.completion {
            ConversationTextCompletion::RemoteArtifactSettledCancellation { evidence } => *evidence,
            _ => return Ok(None),
        };
        validate_receipt(&input.started, input.original.conversation_id)?;
        if durable.conversation_id != input.original.conversation_id
            || input.started.phase != TextGenerationPhase::Started
            || durable.workspace_id != input.started.workspace_id
            || durable.taskrun_id != input.started.taskrun_id
            || durable.attempt_id != input.started.attempt_id
            || durable.user_message_id != input.started.user_message_id
            || durable.assistant_message_id != input.started.assistant_message_id
            || durable.conversation_version
                != input
                    .started
                    .conversation_version
                    .checked_add(1)
                    .ok_or(ConversationTextServiceError::StoredDataUnavailable)?
            || durable.taskrun_version
                != evidence
                    .cancellation_taskrun_version()
                    .checked_add(1)
                    .ok_or(ConversationTextServiceError::StoredDataUnavailable)?
        {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        let replay = self
            .repository
            .reject_text_generation_after_remote_artifact_cancellation(
                crate::ports::RejectTextGenerationAfterRemoteArtifactCancellationCommit {
                    command_id: context.command_id,
                    idempotency_key: context.idempotency_key.clone(),
                    idempotency_scope: scope.clone(),
                    command_fingerprint: *fingerprint,
                    expected_conversation_version: input.started.conversation_version,
                    expected_started_taskrun_version: input.started.taskrun_version,
                    evidence,
                    conversation_events: Vec::new(),
                    taskrun_events: Vec::new(),
                    receipt: durable.clone(),
                },
            )
            .map_err(map_commit)?;
        let receipt = match replay {
            TextGenerationCommitResult::Duplicate { stored_result } => stored_result,
            TextGenerationCommitResult::Committed { .. } => {
                return Err(ConversationTextServiceError::ReceiptMismatch);
            }
        };
        if receipt.conversation_id != input.original.conversation_id {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        Ok(Some(receipt))
    }
}
