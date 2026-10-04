use super::command::NormalizedMutationCommand;
use crate::{MutationIdentity, MutationOperation};

impl NormalizedMutationCommand {
    pub(crate) fn matches_identity(&self, identity: &MutationIdentity) -> bool {
        match self {
            Self::CreateProject { project_id, .. } => {
                identity.operation() == MutationOperation::ProjectCreate
                    && identity.expected_version() == 0
                    && project_id.as_bytes() == identity.target()
            }
            Self::RenameProject {
                project_id,
                expected_version,
                ..
            } => {
                identity.operation() == MutationOperation::ProjectRename
                    && *expected_version == identity.expected_version()
                    && project_id.as_bytes() == identity.target()
            }
            Self::ArchiveProject {
                project_id,
                expected_version,
            } => {
                identity.operation() == MutationOperation::ProjectArchive
                    && *expected_version == identity.expected_version()
                    && project_id.as_bytes() == identity.target()
            }
            Self::DeleteProject {
                project_id,
                expected_version,
            } => {
                identity.operation() == MutationOperation::ProjectDelete
                    && *expected_version == identity.expected_version()
                    && project_id.as_bytes() == identity.target()
            }
            Self::CreateWorkspace { workspace_id, .. } => {
                identity.operation() == MutationOperation::WorkspaceCreate
                    && identity.expected_version() == 0
                    && workspace_id.as_bytes() == identity.target()
            }
            Self::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                ..
            } => {
                identity.operation() == MutationOperation::WorkspaceBindRoot
                    && *expected_version == identity.expected_version()
                    && workspace_id.as_bytes() == identity.target()
            }
            Self::OpenWorkspace {
                workspace_id,
                expected_version,
            } => {
                identity.operation() == MutationOperation::WorkspaceOpen
                    && *expected_version == identity.expected_version()
                    && workspace_id.as_bytes() == identity.target()
            }
            Self::CreateConversation {
                conversation_id, ..
            }
            | Self::CreateTextOnlyConversation {
                conversation_id, ..
            } => {
                identity.operation() == MutationOperation::ConversationCreate
                    && identity.expected_version() == 0
                    && conversation_id.as_bytes() == identity.target()
            }
            Self::GenerateText {
                conversation_id,
                expected_version,
                ..
            } => {
                identity.operation() == MutationOperation::ConversationGenerateText
                    && *expected_version == identity.expected_version()
                    && conversation_id.as_bytes() == identity.target()
            }
            Self::CancelTaskRun { .. }
            | Self::SupersedeUnknownTaskRun { .. }
            | Self::SubmitTaskRun { .. }
            | Self::LegacySubmitTaskRun { .. } => task_run_matches_identity(self, identity),
            Self::ApprovalRespond {
                approval_id,
                expected_version,
                ..
            } => {
                identity.operation() == MutationOperation::ApprovalRespond
                    && *expected_version == identity.expected_version()
                    && approval_id.as_bytes() == identity.target()
            }
        }
    }
}

fn task_run_matches_identity(
    command: &NormalizedMutationCommand,
    identity: &MutationIdentity,
) -> bool {
    match command {
        NormalizedMutationCommand::CancelTaskRun {
            task_run_id,
            expected_version,
        } => {
            identity.operation() == MutationOperation::TaskRunCancel
                && *expected_version == identity.expected_version()
                && task_run_id.as_bytes() == identity.target()
        }
        NormalizedMutationCommand::SupersedeUnknownTaskRun {
            predecessor_task_run_id,
            expected_version,
        } => {
            identity.operation() == MutationOperation::TaskRunUnknownSuccessor
                && *expected_version == identity.expected_version()
                && predecessor_task_run_id.as_bytes() == identity.target()
        }
        NormalizedMutationCommand::SubmitTaskRun {
            conversation_id, ..
        }
        | NormalizedMutationCommand::LegacySubmitTaskRun {
            conversation_id, ..
        } => {
            identity.operation() == MutationOperation::TaskRunSubmit
                && identity.expected_version() == 0
                && conversation_id.as_bytes() == identity.target()
        }
        _ => false,
    }
}
