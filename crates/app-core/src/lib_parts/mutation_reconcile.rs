fn request_matches_anchored_command(
    request: &MutationRequest,
    command: &gocode_local_store::NormalizedMutationCommand,
) -> Result<(), AppCoreError> {
    (request.ledger_command()? == *command)
        .then_some(())
        .ok_or(AppCoreError::MutationUnavailable)
}

fn reconciliation_request_from_anchored(
    identity: CommandIdentity,
    command: &gocode_local_store::NormalizedMutationCommand,
) -> Result<gocode_runtime_client::CommandReconciliationRequest, AppCoreError> {
    use gocode_local_store::NormalizedMutationCommand as Command;
    use gocode_runtime_client::CommandReconciliationRequest as Request;
    let id = |value: &gocode_local_store::BoundedCanonicalId| {
        CanonicalId::parse(std::str::from_utf8(value.as_bytes()).map_err(|_| AppCoreError::MutationUnavailable)?)
            .map_err(|_| AppCoreError::MutationUnavailable)
    };
    match command {
        Command::CreateProject { project_id, display_name } => {
            Request::create_project(identity, id(project_id)?, display_name).map_err(|_| AppCoreError::MutationUnavailable)
        }
        Command::ArchiveProject { project_id, expected_version } => {
            Request::archive_project(identity, id(project_id)?, *expected_version).map_err(|_| AppCoreError::MutationUnavailable)
        }
        Command::DeleteProject { project_id, expected_version } => {
            Request::delete_project(identity, id(project_id)?, *expected_version).map_err(|_| AppCoreError::MutationUnavailable)
        }
        Command::CreateWorkspace { workspace_id, project_id, display_name } => {
            Request::create_workspace(identity, id(workspace_id)?, id(project_id)?, display_name).map_err(|_| AppCoreError::MutationUnavailable)
        }
        Command::BindWorkspaceRoot { workspace_id, expected_version, admission_digest } => {
            Request::bind_workspace_root(identity, id(workspace_id)?, *expected_version, hex::encode(admission_digest)).map_err(|_| AppCoreError::MutationUnavailable)
        }
        Command::OpenWorkspace { workspace_id, expected_version } => {
            Request::open_workspace(identity, id(workspace_id)?, *expected_version).map_err(|_| AppCoreError::MutationUnavailable)
        }
        Command::CreateConversation { conversation_id, workspace_id } => {
            Ok(Request::create_conversation(identity, id(conversation_id)?, id(workspace_id)?))
        }
        Command::GenerateText { conversation_id, expected_version, text } => {
            Request::generate_conversation_text(identity, id(conversation_id)?, *expected_version, text).map_err(|_| AppCoreError::MutationUnavailable)
        }
    }
}

pub(crate) fn reconciliation_outcome_to_ledger(
    command: &gocode_local_store::NormalizedMutationCommand,
    outcome: &gocode_runtime_client::CommandReconciliationOutcome,
) -> Result<gocode_local_store::CanonicalMutationOutcome, AppCoreError> {
    use gocode_local_store::{
        CanonicalMutationOutcome as LedgerOutcome, GenerationAssistant, GenerationFailureReason,
        GenerationTerminal, LedgerMessage, MessageRole,
    };
    use gocode_runtime_client::{
        CommandReconciliationOutcome as Outcome, ConversationGenerationFailureReason,
        ConversationMessageRole,
    };
    let id = |value: CanonicalId| {
        gocode_local_store::BoundedCanonicalId::parse(value.to_string().as_bytes())
            .map_err(|_| AppCoreError::MutationUnavailable)
    };
    let message = |value: &gocode_runtime_client::ConversationMessage| -> Result<LedgerMessage, AppCoreError> {
        Ok(LedgerMessage {
            message_id: id(value.message_id)?,
            role: match value.role {
                ConversationMessageRole::User => MessageRole::User,
                ConversationMessageRole::Assistant => MessageRole::Assistant,
            },
            task_run_id: id(value.task_run_id)?,
            attempt_id: id(value.attempt_id)?,
            text: value.text.clone(),
            committed_at: value.committed_at,
        })
    };
    let outcome = match outcome {
        Outcome::ProjectCreated(value) => LedgerOutcome::ProjectCreate {
            project_id: id(value.project_id())?, new_version: value.new_version(),
        },
        Outcome::ProjectArchived(value) => LedgerOutcome::ProjectArchive {
            project_id: id(value.project_id())?, new_version: value.new_version(),
        },
        Outcome::ProjectDeleted(value) => LedgerOutcome::ProjectDelete {
            project_id: id(value.project_id())?, new_version: value.new_version(),
        },
        Outcome::WorkspaceCreated(value) => LedgerOutcome::WorkspaceCreate {
            workspace_id: id(value.workspace_id())?, new_version: value.new_version(),
        },
        Outcome::WorkspaceRootBound(value) => LedgerOutcome::WorkspaceBindRoot {
            workspace_id: id(value.workspace_id())?, new_version: value.new_version(),
        },
        Outcome::WorkspaceOpened(value) => LedgerOutcome::WorkspaceOpen {
            workspace_id: id(value.workspace_id())?, new_version: value.new_version(),
        },
        Outcome::ConversationCreated(value) => LedgerOutcome::ConversationCreate {
            conversation_id: id(value.conversation_id)?, workspace_id: id(value.workspace_id)?,
            stream_version: value.stream_version, committed_at: value.committed_at,
        },
        Outcome::ConversationTextCompleted(value) => LedgerOutcome::Generation {
            terminal: GenerationTerminal::Completed,
            conversation_id: id(value.conversation_id)?, task_run_id: id(value.task_run_id)?,
            attempt_id: id(value.attempt_id)?,
            conversation_stream_version: value.conversation_stream_version,
            task_run_stream_version: value.task_run_stream_version,
            user_message: message(&value.user_message)?,
            assistant: Box::new(GenerationAssistant::Completed(message(&value.assistant_message)?)),
        },
        Outcome::ConversationTextRejected(value) | Outcome::ConversationTextProhibitedInputRejected(value) => LedgerOutcome::Generation {
            terminal: if matches!(outcome, Outcome::ConversationTextRejected(_)) { GenerationTerminal::Rejected } else { GenerationTerminal::Prohibited },
            conversation_id: id(value.conversation_id)?, task_run_id: id(value.task_run_id)?,
            attempt_id: id(value.attempt_id)?,
            conversation_stream_version: value.conversation_stream_version,
            task_run_stream_version: value.task_run_stream_version,
            user_message: message(&value.user_message)?,
            assistant: Box::new(GenerationAssistant::Rejected {
                reserved_message_id: id(value.reserved_assistant_message_id)?,
                reason: match value.reason {
                    ConversationGenerationFailureReason::ProviderOutputRejected => GenerationFailureReason::ProviderOutputRejected,
                },
            }),
        },
    };
    outcome
        .correlates_to_command(command)
        .then_some(outcome)
        .ok_or(AppCoreError::MutationUnavailable)
}

include!("mutation_reconcile/runtime.rs");
