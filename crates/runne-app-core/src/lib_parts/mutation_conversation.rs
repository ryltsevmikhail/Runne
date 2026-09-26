impl AppCore {
    async fn dispatch_conversation_create_under_operation(
        &self,
        context: &RuntimeOperationContext,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        identity: CommandIdentity,
        idempotency_key: String,
        text_only: bool,
    ) -> Result<runne_runtime_client::ConversationCreated, AppCoreError> {
        let request = conversation_request(
            runne_local_store::MutationOperation::ConversationCreate,
            conversation_id,
            0,
            if text_only {
                CanonicalMutationCommand::CreateTextOnlyConversation { conversation_id, workspace_id }
            } else {
                CanonicalMutationCommand::CreateConversation { conversation_id, workspace_id }
            },
            identity,
            idempotency_key,
        )?;
        match self.dispatch_conversation_under_operation(context, request).await? {
            MutationDispatchResult::ConversationCreated(result) => Ok(result),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

    async fn dispatch_text_generation_under_operation(
        &self,
        context: &RuntimeOperationContext,
        conversation_id: CanonicalId,
        expected_version: u64,
        text: &str,
    ) -> Result<runne_runtime_client::ConversationTextResult, AppCoreError> {
        let command_id = CanonicalId::now_v7();
        let key = command_id.to_string();
        let identity = CommandIdentity::new(command_id, key.clone()).map_err(|_| AppCoreError::InvalidMutation)?;
        let request = conversation_request(
            runne_local_store::MutationOperation::ConversationGenerateText,
            conversation_id,
            expected_version,
            CanonicalMutationCommand::GenerateText { conversation_id, text: text.to_owned() },
            identity,
            key,
        )?;
        match self.dispatch_conversation_under_operation(context, request).await? {
            MutationDispatchResult::TextGenerated(result) => Ok(result),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

    async fn dispatch_conversation_under_operation(
        &self,
        context: &RuntimeOperationContext,
        request: MutationRequest,
    ) -> Result<MutationDispatchResult, AppCoreError> {
        self.require_current_operation_context(context)?;
        let mut lease = self.prepare_mutation_under_operation(request)?;
        let identity_matches = lease.runtime_identity == context.identity;
        let gate_matches = lease.gate_epoch == context.gate_epoch;
        if !identity_matches || !gate_matches {
            return Err(AppCoreError::RuntimeUnavailable);
        }
        self.dispatch_prepared_mutation_under_operation(&mut lease, None, false, false, false)
            .await
    }
}

fn conversation_request(
    operation: runne_local_store::MutationOperation,
    conversation_id: CanonicalId,
    expected_version: u64,
    command: CanonicalMutationCommand,
    identity: CommandIdentity,
    idempotency_key: String,
) -> Result<MutationRequest, AppCoreError> {
    let target = MutationTarget::try_new(
        operation,
        runne_local_store::MutationTargetKind::Conversation,
        runne_local_store::BoundedCanonicalId::parse(conversation_id.to_string().as_bytes())
            .map_err(|_| AppCoreError::InvalidMutation)?,
    )
    .map_err(|_| AppCoreError::InvalidMutation)?;
    Ok(MutationRequest::for_conversation(
        operation,
        target,
        expected_version,
        command,
        identity,
        idempotency_key,
    ))
}
