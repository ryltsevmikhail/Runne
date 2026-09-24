use super::command::NormalizedMutationCommand;
use super::outcome::CanonicalMutationOutcome;

impl CanonicalMutationOutcome {
    #[must_use]
    pub fn correlates_to_command(&self, command: &NormalizedMutationCommand) -> bool {
        simple_matches(self, command) || generation_matches(self, command)
    }
}

#[allow(clippy::too_many_lines)]
fn simple_matches(outcome: &CanonicalMutationOutcome, command: &NormalizedMutationCommand) -> bool {
    match (outcome, command) {
        (
            CanonicalMutationOutcome::ProjectCreate {
                project_id: result,
                new_version,
            },
            NormalizedMutationCommand::CreateProject { project_id, .. },
        ) => result == project_id && *new_version == 1,
        (
            CanonicalMutationOutcome::ProjectRename {
                project_id: result,
                new_version,
            },
            NormalizedMutationCommand::RenameProject {
                project_id,
                expected_version,
                ..
            },
        )
        | (
            CanonicalMutationOutcome::ProjectArchive {
                project_id: result,
                new_version,
            },
            NormalizedMutationCommand::ArchiveProject {
                project_id,
                expected_version,
            },
        )
        | (
            CanonicalMutationOutcome::ProjectDelete {
                project_id: result,
                new_version,
            },
            NormalizedMutationCommand::DeleteProject {
                project_id,
                expected_version,
            },
        ) => result == project_id && expected_version.checked_add(1) == Some(*new_version),
        (
            CanonicalMutationOutcome::WorkspaceCreate {
                workspace_id: result,
                new_version,
            },
            NormalizedMutationCommand::CreateWorkspace { workspace_id, .. },
        ) => result == workspace_id && *new_version == 1,
        (
            CanonicalMutationOutcome::WorkspaceBindRoot {
                workspace_id: result,
                new_version,
            },
            NormalizedMutationCommand::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                ..
            },
        )
        | (
            CanonicalMutationOutcome::WorkspaceOpen {
                workspace_id: result,
                new_version,
            },
            NormalizedMutationCommand::OpenWorkspace {
                workspace_id,
                expected_version,
            },
        ) => result == workspace_id && expected_version.checked_add(1) == Some(*new_version),
        (
            CanonicalMutationOutcome::ConversationCreate {
                conversation_id: result,
                workspace_id: result_workspace,
                stream_version,
                ..
            },
            NormalizedMutationCommand::CreateConversation {
                conversation_id,
                workspace_id,
            },
        ) => result == conversation_id && result_workspace == workspace_id && *stream_version == 1,
        (
            CanonicalMutationOutcome::TaskRunCancellationRequested {
                task_run_id: result,
                new_version,
            },
            NormalizedMutationCommand::CancelTaskRun {
                task_run_id,
                expected_version,
            },
        ) => result == task_run_id && expected_version.checked_add(1) == Some(*new_version),
        (
            CanonicalMutationOutcome::TaskRunSubmitted { new_version, .. },
            NormalizedMutationCommand::SubmitTaskRun { .. }
            | NormalizedMutationCommand::LegacySubmitTaskRun { .. },
        ) => *new_version == 2,
        (
            CanonicalMutationOutcome::ApprovalRespond {
                approval_id: result,
                new_version,
                state,
            },
            NormalizedMutationCommand::ApprovalRespond {
                approval_id,
                expected_version,
                decision,
                ..
            },
        ) => {
            result == approval_id
                && expected_version.checked_add(1) == Some(*new_version)
                && matches!(
                    (decision, state),
                    (
                        super::command::ApprovalDecisionKind::Approve,
                        super::outcome::ApprovalOutcomeState::Approved
                    ) | (
                        super::command::ApprovalDecisionKind::Deny,
                        super::outcome::ApprovalOutcomeState::Denied
                    )
                )
        }
        _ => false,
    }
}

fn generation_matches(
    outcome: &CanonicalMutationOutcome,
    command: &NormalizedMutationCommand,
) -> bool {
    let (
        CanonicalMutationOutcome::Generation {
            terminal,
            conversation_id: result,
            task_run_id,
            attempt_id,
            conversation_stream_version,
            task_run_stream_version,
            user_message,
            assistant,
        },
        NormalizedMutationCommand::GenerateText {
            conversation_id,
            expected_version,
            text,
        },
    ) = (outcome, command)
    else {
        return false;
    };
    result == conversation_id
        && expected_version.checked_add(2) == Some(*conversation_stream_version)
        && *task_run_stream_version == 5
        && user_message.role == super::outcome::MessageRole::User
        && user_message.task_run_id == *task_run_id
        && user_message.attempt_id == *attempt_id
        && user_message.text == *text
        && user_message.committed_at != 0
        && generation_assistant_matches(*terminal, user_message, task_run_id, attempt_id, assistant)
}

/// Daemon event timestamps give `committed_at` millisecond granularity, so a
/// fast provider can append the assistant message within the user message's
/// millisecond. Within one millisecond the daemon's monotonic `UUIDv7` counter
/// (`StoreTransaction::generate_uuid`) still mints the assistant id after the
/// user id, so the lexicographic `(committed_at, message_id)` order proves the
/// generation order even when the millisecond values are equal.
fn committed_order_provable(
    assistant: &super::outcome::LedgerMessage,
    user: &super::outcome::LedgerMessage,
) -> bool {
    assistant.committed_at > user.committed_at
        || (assistant.committed_at == user.committed_at
            && assistant.message_id.as_bytes() > user.message_id.as_bytes())
}

fn generation_assistant_matches(
    terminal: super::outcome::GenerationTerminal,
    user: &super::outcome::LedgerMessage,
    task: &crate::BoundedCanonicalId,
    attempt: &crate::BoundedCanonicalId,
    assistant: &super::outcome::GenerationAssistant,
) -> bool {
    match (terminal, assistant) {
        (
            super::outcome::GenerationTerminal::Completed,
            super::outcome::GenerationAssistant::Completed(value),
        ) => {
            value.role == super::outcome::MessageRole::Assistant
                && value.task_run_id == *task
                && value.attempt_id == *attempt
                && value.message_id != user.message_id
                && committed_order_provable(value, user)
        }
        (
            super::outcome::GenerationTerminal::Rejected
            | super::outcome::GenerationTerminal::Prohibited,
            super::outcome::GenerationAssistant::Rejected {
                reserved_message_id,
                reason,
            },
        ) => {
            *reserved_message_id != user.message_id
                && *reason == super::outcome::GenerationFailureReason::ProviderOutputRejected
        }
        _ => false,
    }
}
