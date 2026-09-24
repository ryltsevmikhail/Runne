fn recovery_request(
    evidence: &runne_local_store::MutationRecoveryEvidence,
) -> Result<MutationRequest, AppCoreError> {
    let key = evidence.idempotency_key();
    let command_id = CanonicalId::parse(key).map_err(|_| AppCoreError::MutationUnavailable)?;
    if command_id.to_string() != key {
        return Err(AppCoreError::MutationUnavailable);
    }
    let identity = CommandIdentity::new(command_id, key.to_owned())
        .map_err(|_| AppCoreError::MutationUnavailable)?;
    let command = canonical_command_from_recovery(evidence.normalized_command())?;
    let request = MutationRequest::for_conversation(
        evidence.operation(),
        evidence.target().clone(),
        evidence.expected_version(),
        command,
        identity,
        key.to_owned(),
    );
    request.validate_invariants()?;
    Ok(request)
}

fn canonical_command_from_recovery(
    command: &runne_local_store::NormalizedMutationCommand,
) -> Result<CanonicalMutationCommand, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Stored;
    match command {
        Stored::CreateProject { .. }
        | Stored::RenameProject { .. }
        | Stored::ArchiveProject { .. }
        | Stored::DeleteProject { .. }
        | Stored::CreateWorkspace { .. }
        | Stored::BindWorkspaceRoot { .. }
        | Stored::OpenWorkspace { .. } => recovery_project_workspace_command(command),
        _ => recovery_conversation_command(command),
    }
}

fn recovery_project_workspace_command(
    command: &runne_local_store::NormalizedMutationCommand,
) -> Result<CanonicalMutationCommand, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Stored;
    let id = recovery_canonical_id;
    Ok(match command {
        Stored::CreateProject {
            project_id,
            display_name,
        } => CanonicalMutationCommand::CreateProject {
            project_id: id(project_id)?,
            display_name: display_name.clone(),
        },
        Stored::RenameProject {
            project_id,
            display_name,
            ..
        } => CanonicalMutationCommand::RenameProject {
            project_id: id(project_id)?,
            display_name: display_name.clone(),
        },
        Stored::ArchiveProject { project_id, .. } => CanonicalMutationCommand::ArchiveProject {
            project_id: id(project_id)?,
        },
        Stored::DeleteProject { project_id, .. } => CanonicalMutationCommand::DeleteProject {
            project_id: id(project_id)?,
        },
        Stored::CreateWorkspace {
            workspace_id,
            project_id,
            display_name,
        } => CanonicalMutationCommand::CreateWorkspace {
            workspace_id: id(workspace_id)?,
            project_id: id(project_id)?,
            display_name: display_name.clone(),
        },
        Stored::BindWorkspaceRoot {
            workspace_id,
            admission_digest,
            ..
        } => CanonicalMutationCommand::BindWorkspaceRoot {
            workspace_id: id(workspace_id)?,
            admission_digest: *admission_digest,
        },
        Stored::OpenWorkspace { workspace_id, .. } => {
            CanonicalMutationCommand::OpenWorkspace {
                workspace_id: id(workspace_id)?,
            }
        }
        _ => return Err(AppCoreError::MutationUnavailable),
    })
}

fn recovery_conversation_command(
    command: &runne_local_store::NormalizedMutationCommand,
) -> Result<CanonicalMutationCommand, AppCoreError> {
    use runne_local_store::NormalizedMutationCommand as Stored;
    let id = recovery_canonical_id;
    Ok(match command {
        Stored::CreateConversation {
            conversation_id,
            workspace_id,
        } => CanonicalMutationCommand::CreateConversation {
            conversation_id: id(conversation_id)?,
            workspace_id: id(workspace_id)?,
        },
        Stored::GenerateText {
            conversation_id,
            text,
            ..
        } => CanonicalMutationCommand::GenerateText {
            conversation_id: id(conversation_id)?,
            text: text.clone(),
        },
        Stored::CancelTaskRun { task_run_id, .. } => CanonicalMutationCommand::CancelTaskRun {
            task_run_id: id(task_run_id)?,
        },
        Stored::SubmitTaskRun {
            conversation_id,
            workspace_id,
            prompt,
        } => CanonicalMutationCommand::SubmitTaskRun {
            conversation_id: id(conversation_id)?,
            workspace_id: id(workspace_id)?,
            prompt: Some(prompt.clone()),
        },
        Stored::LegacySubmitTaskRun {
            conversation_id,
            workspace_id,
        } => CanonicalMutationCommand::SubmitTaskRun {
            conversation_id: id(conversation_id)?,
            workspace_id: id(workspace_id)?,
            prompt: None,
        },
        Stored::ApprovalRespond {
            approval_id,
            decision,
            action_digest,
            policy_revision,
            renderer_generation,
            ..
        } => CanonicalMutationCommand::ApprovalRespond {
            approval_id: id(approval_id)?,
            decision: match decision {
                runne_local_store::ApprovalDecisionKind::Approve => {
                    runne_runtime_client::ApprovalDecisionDto::Approve
                }
                runne_local_store::ApprovalDecisionKind::Deny => {
                    runne_runtime_client::ApprovalDecisionDto::Deny
                }
            },
            action_digest: *action_digest,
            policy_revision: *policy_revision,
            renderer_generation: *renderer_generation,
        },
        Stored::CreateProject { .. }
        | Stored::RenameProject { .. }
        | Stored::ArchiveProject { .. }
        | Stored::DeleteProject { .. }
        | Stored::CreateWorkspace { .. }
        | Stored::BindWorkspaceRoot { .. }
        | Stored::OpenWorkspace { .. } => return Err(AppCoreError::MutationUnavailable),
    })
}

fn recovery_canonical_id(
    value: &runne_local_store::BoundedCanonicalId,
) -> Result<CanonicalId, AppCoreError> {
    CanonicalId::parse(
        std::str::from_utf8(value.as_bytes()).map_err(|_| AppCoreError::MutationUnavailable)?,
    )
    .map_err(|_| AppCoreError::MutationUnavailable)
}
