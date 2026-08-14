impl AppCore {
    async fn send_exact_command(
        &self,
        lease: &PreparedMutationLease,
        recovery: bool,
    ) -> Result<MutationDispatchResult, AppCoreError> {
        let client = if recovery {
            self.recovery_dispatch_client(lease)?
        } else {
            self.final_dispatch_client(lease)?
        };
        lease.request.validate_invariants()?;
        match &lease.request.semantic_command {
            CanonicalMutationCommand::CreateConversation { .. }
            | CanonicalMutationCommand::GenerateText { .. } => self.send_conversation(&client, lease).await,
            CanonicalMutationCommand::CreateProject { .. }
            | CanonicalMutationCommand::ArchiveProject { .. }
            | CanonicalMutationCommand::DeleteProject { .. } => self.send_project(&client, lease).await,
            CanonicalMutationCommand::CreateWorkspace { .. }
            | CanonicalMutationCommand::OpenWorkspace { .. } => self.send_workspace(&client, lease).await,
            CanonicalMutationCommand::BindWorkspaceRoot { .. } => self.send_root_bind(&client, lease).await,
        }
    }

    async fn send_conversation(&self, client: &AuthenticatedRuntimeClient, lease: &PreparedMutationLease) -> Result<MutationDispatchResult, AppCoreError> {
        let unavailable = |_| AppCoreError::RuntimeUnavailable;
        match &lease.request.semantic_command {
            CanonicalMutationCommand::CreateConversation { conversation_id, workspace_id } => client.create_conversation(CreateConversationRequest::new(lease.request.command_identity.clone(), *conversation_id, *workspace_id)).await.map(MutationDispatchResult::ConversationCreated).map_err(unavailable),
            CanonicalMutationCommand::GenerateText { conversation_id, text } => client.generate_text(GenerateTextRequest::new(lease.request.command_identity.clone(), *conversation_id, lease.request.expected_version, text).map_err(|_| AppCoreError::InvalidMutation)?).await.map(MutationDispatchResult::TextGenerated).map_err(unavailable),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

    async fn send_project(&self, client: &AuthenticatedRuntimeClient, lease: &PreparedMutationLease) -> Result<MutationDispatchResult, AppCoreError> {
        let unavailable = |_| AppCoreError::RuntimeUnavailable;
        let request = |id| ExistingProjectRequest::new(lease.request.command_identity.clone(), id, lease.request.expected_version).map_err(|_| AppCoreError::InvalidMutation);
        match &lease.request.semantic_command {
            CanonicalMutationCommand::CreateProject { project_id, display_name } => client.create_project(CreateProjectRequest::new(lease.request.command_identity.clone(), *project_id, display_name).map_err(|_| AppCoreError::InvalidMutation)?).await.map(MutationDispatchResult::Project).map_err(unavailable),
            CanonicalMutationCommand::ArchiveProject { project_id } => client.archive_project(request(*project_id)?).await.map(MutationDispatchResult::Project).map_err(unavailable),
            CanonicalMutationCommand::DeleteProject { project_id } => client.delete_project(request(*project_id)?).await.map(MutationDispatchResult::Project).map_err(unavailable),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

    async fn send_workspace(&self, client: &AuthenticatedRuntimeClient, lease: &PreparedMutationLease) -> Result<MutationDispatchResult, AppCoreError> {
        let unavailable = |_| AppCoreError::RuntimeUnavailable;
        match &lease.request.semantic_command {
            CanonicalMutationCommand::CreateWorkspace { project_id, workspace_id, display_name } => client.create_workspace(CreateWorkspaceRequest::new(lease.request.command_identity.clone(), *project_id, *workspace_id, display_name).map_err(|_| AppCoreError::InvalidMutation)?).await.map(MutationDispatchResult::Workspace).map_err(unavailable),
            CanonicalMutationCommand::OpenWorkspace { workspace_id } => client.open_workspace(ExistingWorkspaceRequest::new(lease.request.command_identity.clone(), *workspace_id, lease.request.expected_version).map_err(|_| AppCoreError::InvalidMutation)?).await.map(MutationDispatchResult::Workspace).map_err(unavailable),
            _ => Err(AppCoreError::InvalidMutation),
        }
    }

    async fn send_root_bind(&self, client: &AuthenticatedRuntimeClient, lease: &PreparedMutationLease) -> Result<MutationDispatchResult, AppCoreError> {
        let CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, .. } = &lease.request.semantic_command else { return Err(AppCoreError::InvalidMutation); };
        if self.runtime_mode != RuntimeMode::Bundled || !gocode_runtime_client::protected_profile_matches(client) { return Err(AppCoreError::RuntimeUnavailable); }
        let finalized = lease.finalized_root.as_ref().ok_or(AppCoreError::InvalidMutation)?;
        if finalized.runtime_identity != lease.runtime_identity || finalized.workspace_id != *workspace_id || finalized.expected_version != lease.request.expected_version || finalized.admission_digest != finalized.admission.admission_digest() { return Err(AppCoreError::RuntimeUnavailable); }
        self.final_dispatch_client(lease)?;
        client.bind_workspace_root(gocode_runtime_client::BindWorkspaceRootRequest::new(lease.request.command_identity.clone(), *workspace_id, lease.request.expected_version, &finalized.admission).map_err(|_| AppCoreError::InvalidMutation)?).await.map(MutationDispatchResult::Workspace).map_err(|_| AppCoreError::RuntimeUnavailable)
    }
}
