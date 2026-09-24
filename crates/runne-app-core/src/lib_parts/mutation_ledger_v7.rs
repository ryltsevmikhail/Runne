impl MutationRequest {
    fn ledger_command(&self) -> Result<runne_local_store::NormalizedMutationCommand, AppCoreError> {
        use runne_local_store::NormalizedMutationCommand as Command;
        let id = |value: CanonicalId| {
            runne_local_store::BoundedCanonicalId::parse(value.to_string().as_bytes())
                .map_err(|_| AppCoreError::InvalidMutation)
        };
        match &self.semantic_command {
            CanonicalMutationCommand::CreateProject { project_id, display_name } => {
                Command::create_project(id(*project_id)?, display_name.clone())
                    .map_err(|_| AppCoreError::InvalidMutation)
            }
            CanonicalMutationCommand::RenameProject { project_id, display_name } => Ok(Command::RenameProject { project_id: id(*project_id)?, expected_version: self.expected_version, display_name: display_name.clone() }),
            CanonicalMutationCommand::ArchiveProject { project_id } => Ok(Command::ArchiveProject {
                project_id: id(*project_id)?,
                expected_version: self.expected_version,
            }),
            CanonicalMutationCommand::DeleteProject { project_id } => Ok(Command::DeleteProject {
                project_id: id(*project_id)?,
                expected_version: self.expected_version,
            }),
            CanonicalMutationCommand::CreateWorkspace { project_id, workspace_id, display_name } => {
                Ok(Command::CreateWorkspace {
                    workspace_id: id(*workspace_id)?,
                    project_id: id(*project_id)?,
                    display_name: display_name.clone(),
                })
            }
            CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, admission_digest } => {
                Command::bind_workspace_root(id(*workspace_id)?, self.expected_version, *admission_digest)
                    .map_err(|_| AppCoreError::InvalidMutation)
            }
            CanonicalMutationCommand::OpenWorkspace { workspace_id } => Ok(Command::OpenWorkspace {
                workspace_id: id(*workspace_id)?,
                expected_version: self.expected_version,
            }),
            CanonicalMutationCommand::CreateConversation { conversation_id, workspace_id } => {
                Ok(Command::CreateConversation {
                    conversation_id: id(*conversation_id)?,
                    workspace_id: id(*workspace_id)?,
                })
            }
            CanonicalMutationCommand::GenerateText { conversation_id, text } => Ok(Command::GenerateText {
                conversation_id: id(*conversation_id)?,
                expected_version: self.expected_version,
                text: text.clone(),
            }),
            CanonicalMutationCommand::CancelTaskRun { task_run_id } => Ok(Command::CancelTaskRun {
                task_run_id: id(*task_run_id)?,
                expected_version: self.expected_version,
            }),
            CanonicalMutationCommand::SubmitTaskRun { conversation_id, workspace_id } => Ok(Command::SubmitTaskRun { conversation_id: id(*conversation_id)?, workspace_id: id(*workspace_id)? }),
            CanonicalMutationCommand::ApprovalRespond { approval_id, decision, action_digest, policy_revision, renderer_generation } => Ok(Command::ApprovalRespond {
                approval_id: id(*approval_id)?,
                expected_version: self.expected_version,
                decision: match decision {
                    runne_runtime_client::ApprovalDecisionDto::Approve => runne_local_store::ApprovalDecisionKind::Approve,
                    runne_runtime_client::ApprovalDecisionDto::Deny => runne_local_store::ApprovalDecisionKind::Deny,
                },
                action_digest: *action_digest,
                policy_revision: *policy_revision,
                renderer_generation: *renderer_generation,
            }),
        }
    }
}

fn ledger_identity(
    binding: MutationAdmissionBinding,
    request: &MutationRequest,
) -> Result<runne_local_store::MutationIdentity, AppCoreError> {
    runne_local_store::MutationIdentity::new(
        binding.runtime_identity_digest,
        binding.principal_digest,
        request.operation,
        request.target.kind(),
        request.target.canonical_id().clone(),
        request.idempotency_key.clone(),
        request.expected_version,
        request.semantic_digest(),
    )
    .map_err(|_| AppCoreError::InvalidMutation)
}
