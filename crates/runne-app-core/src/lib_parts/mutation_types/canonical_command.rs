/// Canonical, normalized command values. DTO construction happens only after
/// the digest has been anchored by the coordinator.
#[derive(Clone, Eq, PartialEq)]
pub enum CanonicalMutationCommand {
    CreateProject {
        project_id: CanonicalId,
        display_name: String,
    },
    RenameProject {
        project_id: CanonicalId,
        display_name: String,
    },
    ArchiveProject {
        project_id: CanonicalId,
    },
    DeleteProject {
        project_id: CanonicalId,
    },
    CreateWorkspace {
        project_id: CanonicalId,
        workspace_id: CanonicalId,
        display_name: String,
    },
    BindWorkspaceRoot {
        workspace_id: CanonicalId,
        admission_digest: [u8; 32],
    },
    OpenWorkspace {
        workspace_id: CanonicalId,
    },
    CreateConversation {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    },
    CreateTextOnlyConversation {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    },
    GenerateText {
        conversation_id: CanonicalId,
        text: String,
    },
    CancelTaskRun {
        task_run_id: CanonicalId,
    },
    SupersedeUnknownTaskRun { predecessor_task_run_id: CanonicalId },
    /// `prompt` is absent only when recovering a pre-prompt tag 12 record.
    SubmitTaskRun {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: Option<String>,
    },
    ApprovalRespond {
        approval_id: CanonicalId,
        decision: runne_runtime_client::ApprovalDecisionDto,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    },
}

impl std::fmt::Debug for CanonicalMutationCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CanonicalMutationCommand(<redacted>)")
    }
}
