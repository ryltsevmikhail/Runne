use super::local_command::LocalCommandWire;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReconciliationBody {
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
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        profile: Option<SelectedProfileWire>,
        #[serde(default)]
        local_command: Option<LocalCommandWire>,
    },
    SupersedeUnknownTaskRun {
        predecessor_task_run_id: String,
        expected_version: u64,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::command_reconciliation) struct SelectedProfileWire {
    pub(super) profile_id: String,
    pub(super) profile_digest: String,
}
