use crate::{ApprovalDecision, CanonicalMessageText, ProjectWorkspaceDisplayNameInput};
use runne_domain::id::{ApprovalId, ConversationId, ProjectId, TaskRunId, WorkspaceId};
use runne_domain::task_run::TaskRunInput;

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
    RenameProject {
        project_id: ProjectId,
        expected_version: u64,
        display_name: &'a ProjectWorkspaceDisplayNameInput,
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
    CreateTextOnlyConversation {
        conversation_id: ConversationId,
        workspace_id: WorkspaceId,
    },
    GenerateConversationText {
        conversation_id: ConversationId,
        expected_version: u64,
        text: &'a CanonicalMessageText,
    },
    CancelTaskRun {
        task_run_id: TaskRunId,
        expected_version: u64,
    },
    SupersedeUnknownTaskRun {
        predecessor_taskrun_id: TaskRunId,
        expected_version: u64,
    },
    SubmitTaskRun {
        conversation_id: ConversationId,
        workspace_id: WorkspaceId,
        input: Option<&'a TaskRunInput>,
    },
    ApprovalDecision {
        approval_id: ApprovalId,
        expected_version: u64,
        decision: ApprovalDecision,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    },
}
