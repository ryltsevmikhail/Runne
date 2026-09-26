impl MutationRequest {
    fn ledger_command(&self) -> Result<runne_local_store::NormalizedMutationCommand, AppCoreError> {
        use CanonicalMutationCommand as Canonical;
        let command = &self.semantic_command;
        let version = self.expected_version;
        match command {
            Canonical::CreateProject { .. }
            | Canonical::RenameProject { .. }
            | Canonical::ArchiveProject { .. }
            | Canonical::DeleteProject { .. } => ledger_project_command(command, version),
            Canonical::CreateWorkspace { .. }
            | Canonical::BindWorkspaceRoot { .. }
            | Canonical::OpenWorkspace { .. } => ledger_workspace_command(command, version),
            _ => ledger_conversation_command(command, version),
        }
    }
}

fn ledger_project_command(
    command: &CanonicalMutationCommand,
    version: u64,
) -> Result<runne_local_store::NormalizedMutationCommand, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Stored;
    match command {
        CanonicalMutationCommand::CreateProject {
            project_id,
            display_name,
        } => Stored::create_project(ledger_id(*project_id)?, display_name.clone())
            .map_err(|_| AppCoreError::InvalidMutation),
        CanonicalMutationCommand::RenameProject {
            project_id,
            display_name,
        } => Ok(Stored::RenameProject {
            project_id: ledger_id(*project_id)?,
            expected_version: version,
            display_name: display_name.clone(),
        }),
        CanonicalMutationCommand::ArchiveProject { project_id } => Ok(Stored::ArchiveProject {
            project_id: ledger_id(*project_id)?,
            expected_version: version,
        }),
        CanonicalMutationCommand::DeleteProject { project_id } => Ok(Stored::DeleteProject {
            project_id: ledger_id(*project_id)?,
            expected_version: version,
        }),
        _ => Err(AppCoreError::InvalidMutation),
    }
}

fn ledger_workspace_command(
    command: &CanonicalMutationCommand,
    version: u64,
) -> Result<runne_local_store::NormalizedMutationCommand, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Stored;
    match command {
        CanonicalMutationCommand::CreateWorkspace {
            project_id,
            workspace_id,
            display_name,
        } => Ok(Stored::CreateWorkspace {
            workspace_id: ledger_id(*workspace_id)?,
            project_id: ledger_id(*project_id)?,
            display_name: display_name.clone(),
        }),
        CanonicalMutationCommand::BindWorkspaceRoot {
            workspace_id,
            admission_digest,
        } => Stored::bind_workspace_root(
            ledger_id(*workspace_id)?,
            version,
            *admission_digest,
        )
        .map_err(|_| AppCoreError::InvalidMutation),
        CanonicalMutationCommand::OpenWorkspace { workspace_id } => Ok(Stored::OpenWorkspace {
            workspace_id: ledger_id(*workspace_id)?,
            expected_version: version,
        }),
        _ => Err(AppCoreError::InvalidMutation),
    }
}

fn ledger_conversation_command(
    command: &CanonicalMutationCommand,
    version: u64,
) -> Result<runne_local_store::NormalizedMutationCommand, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Stored;
    match command {
        CanonicalMutationCommand::CreateConversation {
            conversation_id,
            workspace_id,
        } => Ok(Stored::CreateConversation {
            conversation_id: ledger_id(*conversation_id)?,
            workspace_id: ledger_id(*workspace_id)?,
        }),
        CanonicalMutationCommand::CreateTextOnlyConversation {
            conversation_id,
            workspace_id,
        } => Ok(Stored::CreateTextOnlyConversation {
            conversation_id: ledger_id(*conversation_id)?,
            workspace_id: ledger_id(*workspace_id)?,
        }),
        CanonicalMutationCommand::GenerateText {
            conversation_id,
            text,
        } => Ok(Stored::GenerateText {
            conversation_id: ledger_id(*conversation_id)?,
            expected_version: version,
            text: text.clone(),
        }),
        CanonicalMutationCommand::CancelTaskRun { task_run_id } => Ok(Stored::CancelTaskRun {
            task_run_id: ledger_id(*task_run_id)?,
            expected_version: version,
        }),
        CanonicalMutationCommand::SubmitTaskRun {
            conversation_id,
            workspace_id,
            prompt: Some(prompt),
        } => Ok(Stored::SubmitTaskRun {
            conversation_id: ledger_id(*conversation_id)?,
            workspace_id: ledger_id(*workspace_id)?,
            prompt: prompt.clone(),
        }),
        CanonicalMutationCommand::SubmitTaskRun {
            conversation_id,
            workspace_id,
            prompt: None,
        } => Ok(Stored::LegacySubmitTaskRun {
            conversation_id: ledger_id(*conversation_id)?,
            workspace_id: ledger_id(*workspace_id)?,
        }),
        CanonicalMutationCommand::ApprovalRespond {
            approval_id,
            decision,
            action_digest,
            policy_revision,
            renderer_generation,
        } => Ok(Stored::ApprovalRespond {
            approval_id: ledger_id(*approval_id)?,
            expected_version: version,
            decision: match decision {
                runne_runtime_client::ApprovalDecisionDto::Approve => {
                    runne_local_store::ApprovalDecisionKind::Approve
                }
                runne_runtime_client::ApprovalDecisionDto::Deny => {
                    runne_local_store::ApprovalDecisionKind::Deny
                }
            },
            action_digest: *action_digest,
            policy_revision: *policy_revision,
            renderer_generation: *renderer_generation,
        }),
        _ => Err(AppCoreError::InvalidMutation),
    }
}

fn ledger_id(
    value: CanonicalId,
) -> Result<runne_local_store::BoundedCanonicalId, AppCoreError> {
    runne_local_store::BoundedCanonicalId::parse(value.to_string().as_bytes())
        .map_err(|_| AppCoreError::InvalidMutation)
}
