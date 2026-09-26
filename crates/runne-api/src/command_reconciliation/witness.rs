use super::witness_ref::CommandReconciliationWitnessRef;
use crate::{ApprovalDecision, CanonicalMessageText, ProjectWorkspaceDisplayNameInput};
use runne_domain::id::{ApprovalId, ConversationId, ProjectId, TaskRunId, WorkspaceId};
use runne_domain::task_run::TaskRunInput;

use super::ReconciliationOperation;

/// Validated semantic fields for exactly one supported operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReconciliationWitness {
    inner: Witness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Witness {
    CreateProject(ProjectId, ProjectWorkspaceDisplayNameInput),
    ArchiveProject(ProjectId, u64),
    DeleteProject(ProjectId, u64),
    RenameProject(ProjectId, u64, ProjectWorkspaceDisplayNameInput),
    CreateWorkspace(WorkspaceId, ProjectId, ProjectWorkspaceDisplayNameInput),
    BindWorkspaceRoot(WorkspaceId, u64, [u8; 32]),
    OpenWorkspace(WorkspaceId, u64),
    CreateConversation(ConversationId, WorkspaceId),
    CreateTextOnlyConversation(ConversationId, WorkspaceId),
    GenerateConversationText(ConversationId, u64, CanonicalMessageText),
    CancelTaskRun(TaskRunId, u64),
    SubmitTaskRun(ConversationId, WorkspaceId, Option<TaskRunInput>),
    ApprovalDecision(ApprovalId, u64, ApprovalDecision, [u8; 32], u64, u64),
}

impl CommandReconciliationWitness {
    #[must_use]
    pub const fn create_project(id: ProjectId, name: ProjectWorkspaceDisplayNameInput) -> Self {
        Self {
            inner: Witness::CreateProject(id, name),
        }
    }

    #[must_use]
    pub const fn archive_project(id: ProjectId, version: u64) -> Self {
        Self {
            inner: Witness::ArchiveProject(id, version),
        }
    }

    #[must_use]
    pub const fn delete_project(id: ProjectId, version: u64) -> Self {
        Self {
            inner: Witness::DeleteProject(id, version),
        }
    }

    #[must_use]
    pub const fn rename_project(
        id: ProjectId,
        version: u64,
        name: ProjectWorkspaceDisplayNameInput,
    ) -> Self {
        Self {
            inner: Witness::RenameProject(id, version, name),
        }
    }

    #[must_use]
    pub const fn create_workspace(
        id: WorkspaceId,
        project: ProjectId,
        name: ProjectWorkspaceDisplayNameInput,
    ) -> Self {
        Self {
            inner: Witness::CreateWorkspace(id, project, name),
        }
    }

    #[must_use]
    pub const fn bind_workspace_root(id: WorkspaceId, version: u64, digest: [u8; 32]) -> Self {
        Self {
            inner: Witness::BindWorkspaceRoot(id, version, digest),
        }
    }

    #[must_use]
    pub const fn open_workspace(id: WorkspaceId, version: u64) -> Self {
        Self {
            inner: Witness::OpenWorkspace(id, version),
        }
    }

    #[must_use]
    pub const fn create_conversation(id: ConversationId, workspace: WorkspaceId) -> Self {
        Self {
            inner: Witness::CreateConversation(id, workspace),
        }
    }

    #[must_use]
    pub const fn create_text_only_conversation(id: ConversationId, workspace: WorkspaceId) -> Self {
        Self {
            inner: Witness::CreateTextOnlyConversation(id, workspace),
        }
    }

    #[must_use]
    pub const fn generate_conversation_text(
        id: ConversationId,
        version: u64,
        text: CanonicalMessageText,
    ) -> Self {
        Self {
            inner: Witness::GenerateConversationText(id, version, text),
        }
    }

    #[must_use]
    pub const fn cancel_task_run(id: TaskRunId, version: u64) -> Self {
        Self {
            inner: Witness::CancelTaskRun(id, version),
        }
    }

    #[must_use]
    pub fn submit_task_run(
        conversation: ConversationId,
        workspace: WorkspaceId,
        input: TaskRunInput,
    ) -> Self {
        Self {
            inner: Witness::SubmitTaskRun(conversation, workspace, Some(input)),
        }
    }

    /// Builds a promptless witness for reconciling a historical submit
    /// receipt written before submitted input became part of the command.
    #[must_use]
    pub const fn submit_task_run_legacy(
        conversation: ConversationId,
        workspace: WorkspaceId,
    ) -> Self {
        Self {
            inner: Witness::SubmitTaskRun(conversation, workspace, None),
        }
    }

    #[must_use]
    pub const fn approval_decision(
        id: ApprovalId,
        version: u64,
        decision: ApprovalDecision,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Self {
        Self {
            inner: Witness::ApprovalDecision(
                id,
                version,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            ),
        }
    }

    #[must_use]
    pub const fn operation(&self) -> ReconciliationOperation {
        match self.inner {
            Witness::CreateProject(..) => ReconciliationOperation::CreateProject,
            Witness::ArchiveProject(..) => ReconciliationOperation::ArchiveProject,
            Witness::DeleteProject(..) => ReconciliationOperation::DeleteProject,
            Witness::RenameProject(..) => ReconciliationOperation::RenameProject,
            Witness::CreateWorkspace(..) => ReconciliationOperation::CreateWorkspace,
            Witness::BindWorkspaceRoot(..) => ReconciliationOperation::BindWorkspaceRoot,
            Witness::OpenWorkspace(..) => ReconciliationOperation::OpenWorkspace,
            Witness::CreateConversation(..) => ReconciliationOperation::CreateConversation,
            Witness::CreateTextOnlyConversation(..) => ReconciliationOperation::CreateConversation,
            Witness::GenerateConversationText(..) => {
                ReconciliationOperation::GenerateConversationText
            }
            Witness::CancelTaskRun(..) => ReconciliationOperation::CancelTaskRun,
            Witness::SubmitTaskRun(..) => ReconciliationOperation::SubmitTaskRun,
            Witness::ApprovalDecision(..) => ReconciliationOperation::ApprovalDecision,
        }
    }

    #[must_use]
    pub const fn view(&self) -> CommandReconciliationWitnessRef<'_> {
        match &self.inner {
            Witness::CreateProject(id, name) => CommandReconciliationWitnessRef::CreateProject {
                project_id: *id,
                display_name: name,
            },
            Witness::ArchiveProject(id, expected_version) => {
                CommandReconciliationWitnessRef::ArchiveProject {
                    project_id: *id,
                    expected_version: *expected_version,
                }
            }
            Witness::DeleteProject(id, expected_version) => {
                CommandReconciliationWitnessRef::DeleteProject {
                    project_id: *id,
                    expected_version: *expected_version,
                }
            }
            Witness::RenameProject(id, expected_version, display_name) => {
                CommandReconciliationWitnessRef::RenameProject {
                    project_id: *id,
                    expected_version: *expected_version,
                    display_name,
                }
            }
            Witness::CreateWorkspace(id, project_id, name) => {
                CommandReconciliationWitnessRef::CreateWorkspace {
                    workspace_id: *id,
                    project_id: *project_id,
                    display_name: name,
                }
            }
            Witness::BindWorkspaceRoot(id, expected_version, admission_digest) => {
                CommandReconciliationWitnessRef::BindWorkspaceRoot {
                    workspace_id: *id,
                    expected_version: *expected_version,
                    admission_digest: *admission_digest,
                }
            }
            Witness::OpenWorkspace(id, expected_version) => {
                CommandReconciliationWitnessRef::OpenWorkspace {
                    workspace_id: *id,
                    expected_version: *expected_version,
                }
            }
            Witness::CreateConversation(id, workspace_id) => {
                CommandReconciliationWitnessRef::CreateConversation {
                    conversation_id: *id,
                    workspace_id: *workspace_id,
                }
            }
            Witness::CreateTextOnlyConversation(id, workspace_id) => {
                CommandReconciliationWitnessRef::CreateTextOnlyConversation {
                    conversation_id: *id,
                    workspace_id: *workspace_id,
                }
            }
            Witness::GenerateConversationText(id, expected_version, text) => {
                CommandReconciliationWitnessRef::GenerateConversationText {
                    conversation_id: *id,
                    expected_version: *expected_version,
                    text,
                }
            }
            Witness::CancelTaskRun(id, expected_version) => {
                CommandReconciliationWitnessRef::CancelTaskRun {
                    task_run_id: *id,
                    expected_version: *expected_version,
                }
            }
            Witness::SubmitTaskRun(conversation_id, workspace_id, input) => {
                CommandReconciliationWitnessRef::SubmitTaskRun {
                    conversation_id: *conversation_id,
                    workspace_id: *workspace_id,
                    input: input.as_ref(),
                }
            }
            Witness::ApprovalDecision(
                id,
                expected_version,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            ) => CommandReconciliationWitnessRef::ApprovalDecision {
                approval_id: *id,
                expected_version: *expected_version,
                decision: *decision,
                action_digest: *action_digest,
                policy_revision: *policy_revision,
                renderer_generation: *renderer_generation,
            },
        }
    }
}
