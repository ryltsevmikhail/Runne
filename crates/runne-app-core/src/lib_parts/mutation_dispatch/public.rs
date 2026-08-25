impl AppCore {
    /// Creates one Project through the anchored coordinator.
    ///
    /// # Errors
    ///
    /// Returns a closed storage, runtime, or command validation error.
    pub async fn create_runtime_project(&self, project_id: CanonicalId, display_name: String) -> Result<runne_runtime_client::ProjectCommandAcknowledgement, AppCoreError> {
        self.dispatch_project(MutationRequest::create_project(project_id, display_name)?).await
    }

    /// Creates one Workspace through the anchored coordinator.
    ///
    /// # Errors
    ///
    /// Returns a closed storage, runtime, or command validation error.
    pub async fn create_runtime_workspace(&self, project_id: CanonicalId, workspace_id: CanonicalId, display_name: String) -> Result<runne_runtime_client::WorkspaceCommandAcknowledgement, AppCoreError> {
        self.dispatch_workspace(MutationRequest::create_workspace(project_id, workspace_id, display_name)?).await
    }

    /// Opens one Workspace through the anchored coordinator.
    ///
    /// # Errors
    ///
    /// Returns a closed storage, runtime, or command validation error.
    pub async fn open_runtime_workspace(&self, workspace_id: CanonicalId, expected_version: u64) -> Result<runne_runtime_client::WorkspaceCommandAcknowledgement, AppCoreError> {
        self.dispatch_workspace(MutationRequest::open_workspace(workspace_id, expected_version)?).await
    }

    async fn dispatch_project(&self, request: MutationRequest) -> Result<runne_runtime_client::ProjectCommandAcknowledgement, AppCoreError> {
        let lease = self.prepare_mutation(request).await?;
        match self.dispatch_prepared_mutation(lease).await? {
            MutationDispatchResult::Project(value) => Ok(value),
            MutationDispatchResult::Workspace(_) | MutationDispatchResult::ConversationCreated(_) | MutationDispatchResult::TextGenerated(_) | MutationDispatchResult::TaskRunCancellationRequested(_) | MutationDispatchResult::ApprovalDecision(_) => Err(AppCoreError::InvalidMutation),
        }
    }

    async fn dispatch_workspace(&self, request: MutationRequest) -> Result<runne_runtime_client::WorkspaceCommandAcknowledgement, AppCoreError> {
        let lease = self.prepare_mutation(request).await?;
        match self.dispatch_prepared_mutation(lease).await? {
            MutationDispatchResult::Workspace(value) => Ok(value),
            MutationDispatchResult::Project(_) | MutationDispatchResult::ConversationCreated(_) | MutationDispatchResult::TextGenerated(_) | MutationDispatchResult::TaskRunCancellationRequested(_) | MutationDispatchResult::ApprovalDecision(_) => Err(AppCoreError::InvalidMutation),
        }
    }

    /// Performs the one centralized runne-runtime-client mutation dispatch.
    async fn dispatch_prepared_mutation(&self, mut lease: PreparedMutationLease) -> Result<MutationDispatchResult, AppCoreError> {
        let _operation = self.runtime_operation.lock().await;
        self.dispatch_prepared_mutation_under_operation(&mut lease, None, false, false, false).await
    }
}
