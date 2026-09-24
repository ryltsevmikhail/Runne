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
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::TaskRunSubmit,
            runne_local_store::MutationTargetKind::Conversation,
            conversation_id,
            0,
            CanonicalMutationCommand::SubmitTaskRun {
                conversation_id,
                workspace_id,
            },
        )
    }
}
