use crate::BoundedCanonicalId;

use super::ApprovalOutcomeState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMutationOutcome {
    ProjectCreate {
        project_id: BoundedCanonicalId,
        new_version: u64,
    },
    ProjectRename {
        project_id: BoundedCanonicalId,
        new_version: u64,
    },
    ProjectArchive {
        project_id: BoundedCanonicalId,
        new_version: u64,
    },
    ProjectDelete {
        project_id: BoundedCanonicalId,
        new_version: u64,
    },
    WorkspaceCreate {
        workspace_id: BoundedCanonicalId,
        new_version: u64,
    },
    WorkspaceBindRoot {
        workspace_id: BoundedCanonicalId,
        new_version: u64,
    },
    WorkspaceOpen {
        workspace_id: BoundedCanonicalId,
        new_version: u64,
    },
    ConversationCreate {
        conversation_id: BoundedCanonicalId,
        workspace_id: BoundedCanonicalId,
        stream_version: u64,
        committed_at: u64,
    },
    Generation {
        terminal: GenerationTerminal,
        conversation_id: BoundedCanonicalId,
        task_run_id: BoundedCanonicalId,
        attempt_id: BoundedCanonicalId,
        conversation_stream_version: u64,
        task_run_stream_version: u64,
        user_message: LedgerMessage,
        assistant: Box<GenerationAssistant>,
    },
    TaskRunCancellationRequested {
        task_run_id: BoundedCanonicalId,
        new_version: u64,
    },
    TaskRunSubmitted {
        task_run_id: BoundedCanonicalId,
        new_version: u64,
    },
    TaskRunUnknownSuccessorCreated {
        predecessor_task_run_id: BoundedCanonicalId,
        successor_task_run_id: BoundedCanonicalId,
        predecessor_version: u64,
        successor_version: u64,
    },
    TaskRunUnknownSuccessorCreatedLegacy {
        predecessor_task_run_id: BoundedCanonicalId,
        successor_task_run_id: BoundedCanonicalId,
        new_version: u64,
    },
    ApprovalRespond {
        approval_id: BoundedCanonicalId,
        new_version: u64,
        state: ApprovalOutcomeState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationTerminal {
    Completed,
    Rejected,
    Prohibited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerMessage {
    pub message_id: BoundedCanonicalId,
    pub role: MessageRole,
    pub task_run_id: BoundedCanonicalId,
    pub attempt_id: BoundedCanonicalId,
    pub text: String,
    pub committed_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationAssistant {
    Completed(LedgerMessage),
    Rejected {
        reserved_message_id: BoundedCanonicalId,
        reason: GenerationFailureReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationFailureReason {
    ProviderOutputRejected,
    ProviderExecutionRejected,
    ProviderExecutionFailed,
    ProviderAccountingUnknown,
    Cancelled,
}
