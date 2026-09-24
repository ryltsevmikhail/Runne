use runne_local_store::NormalizedMutationCommand as Command;
use runne_runtime_client::CommandReconciliationRequest as Request;

fn reconciliation_request_from_anchored(
    identity: &CommandIdentity,
    command: &runne_local_store::NormalizedMutationCommand,
) -> Result<Request, AppCoreError> {
        task_run_reconciliation_request(identity, command)
        .or_else(|| workspace_reconciliation_request(identity, command))
        .or_else(|| standard_reconciliation_request(identity, command))
        .unwrap_or(Err(AppCoreError::MutationUnavailable))
}

fn task_run_reconciliation_request(
    identity: &CommandIdentity,
    command: &Command,
) -> Option<Result<Request, AppCoreError>> {
    let id = |value: &runne_local_store::BoundedCanonicalId| canonical_id(value).ok();
    match command {
        Command::CancelTaskRun {
            task_run_id,
            expected_version,
        } => Some(Ok(Request::cancel_task_run(
            identity.clone(),
            id(task_run_id)?,
            *expected_version,
        ))),
        Command::SubmitTaskRun {
            conversation_id,
            workspace_id,
            prompt,
        } => Some(
            Request::submit_task_run(
                identity.clone(),
                id(conversation_id)?,
                id(workspace_id)?,
                prompt.clone(),
            )
            .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::LegacySubmitTaskRun {
            conversation_id,
            workspace_id,
        } => Some(Ok(Request::submit_task_run_legacy(
            identity.clone(),
            id(conversation_id)?,
            id(workspace_id)?,
        ))),
        _ => None,
    }
}

fn workspace_reconciliation_request(
    identity: &CommandIdentity,
    command: &Command,
) -> Option<Result<Request, AppCoreError>> {
    let id = |value: &runne_local_store::BoundedCanonicalId| canonical_id(value).ok();
    match command {
        Command::CreateWorkspace {
            workspace_id,
            project_id,
            display_name,
        } => Some(
            Request::create_workspace(
                identity.clone(),
                id(workspace_id)?,
                id(project_id)?,
                display_name,
            )
            .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::BindWorkspaceRoot {
            workspace_id,
            expected_version,
            admission_digest,
        } => Some(
            Request::bind_workspace_root(
                identity.clone(),
                id(workspace_id)?,
                *expected_version,
                hex::encode(admission_digest),
            )
            .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::OpenWorkspace {
            workspace_id,
            expected_version,
        } => Some(
            Request::open_workspace(identity.clone(), id(workspace_id)?, *expected_version)
                .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        _ => None,
    }
}

fn standard_reconciliation_request(
    identity: &CommandIdentity,
    command: &Command,
) -> Option<Result<Request, AppCoreError>> {
    let id = |value: &runne_local_store::BoundedCanonicalId| canonical_id(value).ok();
    match command {
        Command::CreateProject {
            project_id,
            display_name,
        } => Some(
            Request::create_project(identity.clone(), id(project_id)?, display_name)
                .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::RenameProject {
            project_id,
            expected_version,
            display_name,
        } => Some(
            Request::rename_project(identity.clone(), id(project_id)?, *expected_version, display_name)
                .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::ArchiveProject {
            project_id,
            expected_version,
        } => Some(
            Request::archive_project(identity.clone(), id(project_id)?, *expected_version)
                .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::DeleteProject {
            project_id,
            expected_version,
        } => Some(
            Request::delete_project(identity.clone(), id(project_id)?, *expected_version)
                .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::CreateConversation {
            conversation_id,
            workspace_id,
        } => Some(Ok(Request::create_conversation(
            identity.clone(),
            id(conversation_id)?,
            id(workspace_id)?,
        ))),
        Command::GenerateText {
            conversation_id,
            expected_version,
            text,
        } => Some(
            Request::generate_conversation_text(
                identity.clone(),
                id(conversation_id)?,
                *expected_version,
                text,
            )
            .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::ApprovalRespond {
            approval_id,
            expected_version,
            decision,
            action_digest,
            policy_revision,
            renderer_generation,
        } => Some(
            Request::approval_decision(
                identity.clone(),
                id(approval_id)?,
                *expected_version,
                match decision {
                    runne_local_store::ApprovalDecisionKind::Approve => {
                        runne_runtime_client::ApprovalDecisionDto::Approve
                    }
                    runne_local_store::ApprovalDecisionKind::Deny => {
                        runne_runtime_client::ApprovalDecisionDto::Deny
                    }
                },
                *action_digest,
                *policy_revision,
                *renderer_generation,
            )
            .map_err(|_| AppCoreError::MutationUnavailable),
        ),
        Command::BindWorkspaceRoot { .. }
        | Command::OpenWorkspace { .. }
        | Command::CreateWorkspace { .. }
        | Command::CancelTaskRun { .. }
        | Command::SubmitTaskRun { .. }
        | Command::LegacySubmitTaskRun { .. } => None,
    }
}

fn canonical_id(
    value: &runne_local_store::BoundedCanonicalId,
) -> Result<CanonicalId, AppCoreError> {
    CanonicalId::parse(
        std::str::from_utf8(value.as_bytes()).map_err(|_| AppCoreError::MutationUnavailable)?,
    )
    .map_err(|_| AppCoreError::MutationUnavailable)
}
