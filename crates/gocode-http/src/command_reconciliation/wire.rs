use gocode_api::{
    CanonicalMessageText, CommandReconciliationWitness, ProjectWorkspaceDisplayNameInput,
};
use gocode_domain::id::{ConversationId, ProjectId, WorkspaceId};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum ReconciliationBody {
    CreateProject {
        project_id: String,
        display_name: String,
    },
    ArchiveProject {
        project_id: String,
        expected_version: u64,
    },
    DeleteProject {
        project_id: String,
        expected_version: u64,
    },
    CreateWorkspace {
        workspace_id: String,
        project_id: String,
        display_name: String,
    },
    BindWorkspaceRoot {
        workspace_id: String,
        expected_version: u64,
        admission_digest: String,
    },
    OpenWorkspace {
        workspace_id: String,
        expected_version: u64,
    },
    CreateConversation {
        conversation_id: String,
        workspace_id: String,
    },
    GenerateConversationText {
        conversation_id: String,
        expected_version: u64,
        text: String,
    },
}
impl ReconciliationBody {
    pub(super) fn witness(self) -> Option<CommandReconciliationWitness> {
        match self {
            Self::CreateProject {
                project_id,
                display_name,
            } => Some(CommandReconciliationWitness::create_project(
                project(&project_id)?,
                name(display_name)?,
            )),
            Self::ArchiveProject {
                project_id,
                expected_version,
            } => Some(CommandReconciliationWitness::archive_project(
                project(&project_id)?,
                version(expected_version)?,
            )),
            Self::DeleteProject {
                project_id,
                expected_version,
            } => Some(CommandReconciliationWitness::delete_project(
                project(&project_id)?,
                version(expected_version)?,
            )),
            Self::CreateWorkspace {
                workspace_id,
                project_id,
                display_name,
            } => Some(CommandReconciliationWitness::create_workspace(
                workspace(&workspace_id)?,
                project(&project_id)?,
                name(display_name)?,
            )),
            Self::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                admission_digest,
            } => Some(CommandReconciliationWitness::bind_workspace_root(
                workspace(&workspace_id)?,
                version(expected_version)?,
                digest(&admission_digest)?,
            )),
            Self::OpenWorkspace {
                workspace_id,
                expected_version,
            } => Some(CommandReconciliationWitness::open_workspace(
                workspace(&workspace_id)?,
                version(expected_version)?,
            )),
            Self::CreateConversation {
                conversation_id,
                workspace_id,
            } => Some(CommandReconciliationWitness::create_conversation(
                conversation(&conversation_id)?,
                workspace(&workspace_id)?,
            )),
            Self::GenerateConversationText {
                conversation_id,
                expected_version,
                text,
            } => Some(CommandReconciliationWitness::generate_conversation_text(
                conversation(&conversation_id)?,
                version(expected_version)?,
                CanonicalMessageText::new(text).ok()?,
            )),
        }
    }
}
fn project(value: &str) -> Option<ProjectId> {
    value.parse().ok()
}
fn workspace(value: &str) -> Option<WorkspaceId> {
    value.parse().ok()
}
fn conversation(value: &str) -> Option<ConversationId> {
    value.parse().ok()
}
fn version(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}
fn name(value: String) -> Option<ProjectWorkspaceDisplayNameInput> {
    ProjectWorkspaceDisplayNameInput::new(value).ok()
}
fn digest(value: &str) -> Option<[u8; 32]> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| hex::decode(value).ok()?.try_into().ok())?
}
