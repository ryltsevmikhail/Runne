use runne_api::{
    ApprovalDecision, CanonicalMessageText, CommandReconciliationWitness,
    ProjectWorkspaceDisplayNameInput,
};
use runne_domain::id::{ApprovalId, ConversationId, ProjectId, WorkspaceId};
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
    RenameProject {
        project_id: String,
        expected_version: u64,
        display_name: String,
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
    CreateTextOnlyConversation {
        conversation_id: String,
        workspace_id: String,
    },
    GenerateConversationText {
        conversation_id: String,
        expected_version: u64,
        text: String,
    },
    SubmitTaskRun {
        conversation_id: String,
        workspace_id: String,
        prompt: Option<String>,
    },
    ApprovalDecision {
        approval_id: String,
        expected_version: u64,
        decision: String,
        action_digest: String,
        policy_revision: u64,
        renderer_generation: u64,
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
            Self::RenameProject {
                project_id,
                expected_version,
                display_name,
            } => Some(CommandReconciliationWitness::rename_project(
                project(&project_id)?,
                version(expected_version)?,
                name(display_name)?,
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
            Self::CreateTextOnlyConversation {
                conversation_id,
                workspace_id,
            } => Some(CommandReconciliationWitness::create_text_only_conversation(
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
            Self::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt,
            } => {
                let conversation_id = conversation(&conversation_id)?;
                let workspace_id = workspace(&workspace_id)?;
                match prompt {
                    Some(prompt) => Some(CommandReconciliationWitness::submit_task_run(
                        conversation_id,
                        workspace_id,
                        runne_domain::task_run::TaskRunInput::new(prompt).ok()?,
                    )),
                    None => Some(CommandReconciliationWitness::submit_task_run_legacy(
                        conversation_id,
                        workspace_id,
                    )),
                }
            }
            Self::ApprovalDecision {
                approval_id,
                expected_version,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            } => Some(CommandReconciliationWitness::approval_decision(
                approval(&approval_id)?,
                version(expected_version)?,
                match decision.as_str() {
                    "approve" => ApprovalDecision::Approve,
                    "deny" => ApprovalDecision::Deny,
                    _ => return None,
                },
                digest(&action_digest)?,
                version(policy_revision)?,
                version(renderer_generation)?,
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
fn approval(value: &str) -> Option<ApprovalId> {
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
