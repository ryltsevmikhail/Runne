use crate::{CanonicalMessageText, ProjectWorkspaceDisplayNameInput};
use gocode_domain::id::{ConversationId, ProjectId, WorkspaceId};

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
    CreateWorkspace(WorkspaceId, ProjectId, ProjectWorkspaceDisplayNameInput),
    BindWorkspaceRoot(WorkspaceId, u64, [u8; 32]),
    OpenWorkspace(WorkspaceId, u64),
    CreateConversation(ConversationId, WorkspaceId),
    GenerateConversationText(ConversationId, u64, CanonicalMessageText),
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
    pub const fn operation(&self) -> ReconciliationOperation {
        match self.inner {
            Witness::CreateProject(..) => ReconciliationOperation::CreateProject,
            Witness::ArchiveProject(..) => ReconciliationOperation::ArchiveProject,
            Witness::DeleteProject(..) => ReconciliationOperation::DeleteProject,
            Witness::CreateWorkspace(..) => ReconciliationOperation::CreateWorkspace,
            Witness::BindWorkspaceRoot(..) => ReconciliationOperation::BindWorkspaceRoot,
            Witness::OpenWorkspace(..) => ReconciliationOperation::OpenWorkspace,
            Witness::CreateConversation(..) => ReconciliationOperation::CreateConversation,
            Witness::GenerateConversationText(..) => {
                ReconciliationOperation::GenerateConversationText
            }
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
            Witness::GenerateConversationText(id, expected_version, text) => {
                CommandReconciliationWitnessRef::GenerateConversationText {
                    conversation_id: *id,
                    expected_version: *expected_version,
                    text,
                }
            }
        }
    }
}

/// Borrowed typed semantic fields for an authoritative store adapter.
#[derive(Debug, Clone, Copy)]
pub enum CommandReconciliationWitnessRef<'a> {
    CreateProject {
        project_id: ProjectId,
        display_name: &'a ProjectWorkspaceDisplayNameInput,
    },
    ArchiveProject {
        project_id: ProjectId,
        expected_version: u64,
    },
    DeleteProject {
        project_id: ProjectId,
        expected_version: u64,
    },
    CreateWorkspace {
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        display_name: &'a ProjectWorkspaceDisplayNameInput,
    },
    BindWorkspaceRoot {
        workspace_id: WorkspaceId,
        expected_version: u64,
        admission_digest: [u8; 32],
    },
    OpenWorkspace {
        workspace_id: WorkspaceId,
        expected_version: u64,
    },
    CreateConversation {
        conversation_id: ConversationId,
        workspace_id: WorkspaceId,
    },
    GenerateConversationText {
        conversation_id: ConversationId,
        expected_version: u64,
        text: &'a CanonicalMessageText,
    },
}
