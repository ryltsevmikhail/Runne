impl MutationRequest {
    /// Creates an AppCore-owned normalized task submission request.
    ///
    /// # Errors
    ///
    /// Returns an error when the conversation or workspace ID cannot be
    /// represented as a valid mutation target or command.
    pub fn submit_task_run(
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: String,
    ) -> Result<Self, AppCoreError> {
        if prompt.trim().is_empty() || prompt.len() > runne_api::MAX_TASK_RUN_PROMPT_BYTES {
            return Err(AppCoreError::InvalidMutation);
        }
        Self::new(
            runne_local_store::MutationOperation::TaskRunSubmit,
            runne_local_store::MutationTargetKind::Conversation,
            conversation_id,
            0,
            CanonicalMutationCommand::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt: Some(prompt),
            },
        )
    }

    /// Creates a submit whose durable command identity is supplied by the
    /// native managed-task preflight token.
    ///
    /// # Errors
    /// Returns an error when the identity, prompt, or scope is invalid.
    pub fn submit_task_run_with_identity(
        command_id: CanonicalId,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: String,
    ) -> Result<Self, AppCoreError> {
        if prompt.trim().is_empty() || prompt.len() > runne_api::MAX_TASK_RUN_PROMPT_BYTES {
            return Err(AppCoreError::InvalidMutation);
        }
        let idempotency_key = command_id.to_string();
        let identity =
            runne_runtime_client::CommandIdentity::new(command_id, idempotency_key.clone())
                .map_err(|_| AppCoreError::InvalidMutation)?;
        let target = MutationTarget::try_new(
            runne_local_store::MutationOperation::TaskRunSubmit,
            runne_local_store::MutationTargetKind::Conversation,
            runne_local_store::BoundedCanonicalId::parse(conversation_id.to_string().as_bytes())
                .map_err(|_| AppCoreError::InvalidMutation)?,
        )
        .map_err(|_| AppCoreError::InvalidMutation)?;
        Ok(Self::for_conversation(
            runne_local_store::MutationOperation::TaskRunSubmit,
            target,
            0,
            CanonicalMutationCommand::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt: Some(prompt),
            },
            identity,
            idempotency_key,
        ))
    }
}
