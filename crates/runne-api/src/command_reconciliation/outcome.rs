use crate::{
    ApprovalDecisionAck, CanonicalConversationMessage, ConversationCreatedAck,
    ConversationTextResult, ProjectCommandAck, TaskRunCommandAck, WorkspaceCommandAck,
};
use runne_domain::conversation::GenerationFailureReason;
use runne_domain::id::{AttemptId, ConversationId, MessageId, TaskRunId};

use super::ReconciliationOperation;

/// Durable terminal text outcome; rejection retains its reserved assistant identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoritativeTextGenerationOutcome {
    Completed(ConversationTextResult),
    Rejected {
        conversation_id: ConversationId,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        conversation_stream_version: u64,
        taskrun_stream_version: u64,
        user_message: CanonicalConversationMessage,
        reserved_assistant_message_id: MessageId,
        reason: GenerationFailureReason,
    },
    ProhibitedInputRejected {
        conversation_id: ConversationId,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        conversation_stream_version: u64,
        taskrun_stream_version: u64,
        user_message: CanonicalConversationMessage,
        reserved_assistant_message_id: MessageId,
        reason: GenerationFailureReason,
    },
}

/// Exact durable outcome for one supported reconciliation operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeCommandOutcome {
    inner: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    ProjectCreated(ProjectCommandAck),
    ProjectArchived(ProjectCommandAck),
    ProjectDeleted(ProjectCommandAck),
    ProjectRenamed(ProjectCommandAck),
    WorkspaceCreated(WorkspaceCommandAck),
    WorkspaceRootBound(WorkspaceCommandAck),
    WorkspaceOpened(WorkspaceCommandAck),
    ConversationCreated(ConversationCreatedAck),
    ConversationText(AuthoritativeTextGenerationOutcome),
    TaskRunCancellationRequested(TaskRunCommandAck),
    TaskRunSubmitted(TaskRunCommandAck),
    UnknownSuccessorCreated(TaskRunCommandAck),
    ApprovalDecision(ApprovalDecisionAck),
}

impl AuthoritativeCommandOutcome {
    #[must_use]
    pub const fn project_created(value: ProjectCommandAck) -> Self {
        Self {
            inner: Outcome::ProjectCreated(value),
        }
    }
    #[must_use]
    pub const fn project_archived(value: ProjectCommandAck) -> Self {
        Self {
            inner: Outcome::ProjectArchived(value),
        }
    }
    #[must_use]
    pub const fn project_deleted(value: ProjectCommandAck) -> Self {
        Self {
            inner: Outcome::ProjectDeleted(value),
        }
    }
    #[must_use]
    pub const fn project_renamed(value: ProjectCommandAck) -> Self {
        Self {
            inner: Outcome::ProjectRenamed(value),
        }
    }
    #[must_use]
    pub const fn workspace_created(value: WorkspaceCommandAck) -> Self {
        Self {
            inner: Outcome::WorkspaceCreated(value),
        }
    }
    #[must_use]
    pub const fn workspace_root_bound(value: WorkspaceCommandAck) -> Self {
        Self {
            inner: Outcome::WorkspaceRootBound(value),
        }
    }
    #[must_use]
    pub const fn workspace_opened(value: WorkspaceCommandAck) -> Self {
        Self {
            inner: Outcome::WorkspaceOpened(value),
        }
    }
    #[must_use]
    pub const fn conversation_created(value: ConversationCreatedAck) -> Self {
        Self {
            inner: Outcome::ConversationCreated(value),
        }
    }
    #[must_use]
    pub const fn conversation_text(value: AuthoritativeTextGenerationOutcome) -> Self {
        Self {
            inner: Outcome::ConversationText(value),
        }
    }
    #[must_use]
    pub const fn task_run_cancellation_requested(value: TaskRunCommandAck) -> Self {
        Self {
            inner: Outcome::TaskRunCancellationRequested(value),
        }
    }
    #[must_use]
    pub const fn task_run_submitted(value: TaskRunCommandAck) -> Self {
        Self {
            inner: Outcome::TaskRunSubmitted(value),
        }
    }
    #[must_use]
    pub const fn unknown_successor_created(value: TaskRunCommandAck) -> Self {
        Self {
            inner: Outcome::UnknownSuccessorCreated(value),
        }
    }
    #[must_use]
    pub const fn approval_decision(value: ApprovalDecisionAck) -> Self {
        Self {
            inner: Outcome::ApprovalDecision(value),
        }
    }

    #[must_use]
    pub const fn operation(&self) -> ReconciliationOperation {
        match self.inner {
            Outcome::ProjectCreated(_) => ReconciliationOperation::CreateProject,
            Outcome::ProjectArchived(_) => ReconciliationOperation::ArchiveProject,
            Outcome::ProjectDeleted(_) => ReconciliationOperation::DeleteProject,
            Outcome::ProjectRenamed(_) => ReconciliationOperation::RenameProject,
            Outcome::WorkspaceCreated(_) => ReconciliationOperation::CreateWorkspace,
            Outcome::WorkspaceRootBound(_) => ReconciliationOperation::BindWorkspaceRoot,
            Outcome::WorkspaceOpened(_) => ReconciliationOperation::OpenWorkspace,
            Outcome::ConversationCreated(_) => ReconciliationOperation::CreateConversation,
            Outcome::ConversationText(_) => ReconciliationOperation::GenerateConversationText,
            Outcome::TaskRunCancellationRequested(_) => ReconciliationOperation::CancelTaskRun,
            Outcome::TaskRunSubmitted(_) => ReconciliationOperation::SubmitTaskRun,
            Outcome::UnknownSuccessorCreated(_) => ReconciliationOperation::SupersedeUnknownTaskRun,
            Outcome::ApprovalDecision(_) => ReconciliationOperation::ApprovalDecision,
        }
    }
    #[must_use]
    pub const fn view(&self) -> AuthoritativeCommandOutcomeRef<'_> {
        match &self.inner {
            Outcome::ProjectCreated(value) => AuthoritativeCommandOutcomeRef::ProjectCreated(value),
            Outcome::ProjectArchived(value) => {
                AuthoritativeCommandOutcomeRef::ProjectArchived(value)
            }
            Outcome::ProjectDeleted(value) => AuthoritativeCommandOutcomeRef::ProjectDeleted(value),
            Outcome::ProjectRenamed(value) => AuthoritativeCommandOutcomeRef::ProjectRenamed(value),
            Outcome::WorkspaceCreated(value) => {
                AuthoritativeCommandOutcomeRef::WorkspaceCreated(value)
            }
            Outcome::WorkspaceRootBound(value) => {
                AuthoritativeCommandOutcomeRef::WorkspaceRootBound(value)
            }
            Outcome::WorkspaceOpened(value) => {
                AuthoritativeCommandOutcomeRef::WorkspaceOpened(value)
            }
            Outcome::ConversationCreated(value) => {
                AuthoritativeCommandOutcomeRef::ConversationCreated(value)
            }
            Outcome::ConversationText(value) => {
                AuthoritativeCommandOutcomeRef::ConversationText(value.view())
            }
            Outcome::TaskRunCancellationRequested(value) => {
                AuthoritativeCommandOutcomeRef::TaskRunCancellationRequested(value)
            }
            Outcome::TaskRunSubmitted(value) => {
                AuthoritativeCommandOutcomeRef::TaskRunSubmitted(value)
            }
            Outcome::UnknownSuccessorCreated(value) => {
                AuthoritativeCommandOutcomeRef::UnknownSuccessorCreated(value)
            }
            Outcome::ApprovalDecision(value) => {
                AuthoritativeCommandOutcomeRef::ApprovalDecision(value)
            }
        }
    }
}
/// Borrowed durable outcome projection for transport adapters.
#[derive(Debug, Clone, Copy)]
pub enum AuthoritativeCommandOutcomeRef<'a> {
    ProjectCreated(&'a ProjectCommandAck),
    ProjectArchived(&'a ProjectCommandAck),
    ProjectDeleted(&'a ProjectCommandAck),
    ProjectRenamed(&'a ProjectCommandAck),
    WorkspaceCreated(&'a WorkspaceCommandAck),
    WorkspaceRootBound(&'a WorkspaceCommandAck),
    WorkspaceOpened(&'a WorkspaceCommandAck),
    ConversationCreated(&'a ConversationCreatedAck),
    ConversationText(AuthoritativeTextGenerationOutcomeRef<'a>),
    TaskRunCancellationRequested(&'a TaskRunCommandAck),
    TaskRunSubmitted(&'a TaskRunCommandAck),
    UnknownSuccessorCreated(&'a TaskRunCommandAck),
    ApprovalDecision(&'a ApprovalDecisionAck),
}
#[derive(Debug, Clone, Copy)]
pub enum AuthoritativeTextGenerationOutcomeRef<'a> {
    Completed(&'a ConversationTextResult),
    Rejected {
        conversation_id: ConversationId,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        conversation_stream_version: u64,
        taskrun_stream_version: u64,
        user_message: &'a CanonicalConversationMessage,
        reserved_assistant_message_id: MessageId,
        reason: GenerationFailureReason,
    },
    ProhibitedInputRejected {
        conversation_id: ConversationId,
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        conversation_stream_version: u64,
        taskrun_stream_version: u64,
        user_message: &'a CanonicalConversationMessage,
        reserved_assistant_message_id: MessageId,
        reason: GenerationFailureReason,
    },
}
impl AuthoritativeTextGenerationOutcome {
    #[must_use]
    pub const fn view(&self) -> AuthoritativeTextGenerationOutcomeRef<'_> {
        match self {
            Self::Completed(value) => AuthoritativeTextGenerationOutcomeRef::Completed(value),
            Self::Rejected {
                conversation_id,
                taskrun_id,
                attempt_id,
                conversation_stream_version,
                taskrun_stream_version,
                user_message,
                reserved_assistant_message_id,
                reason,
            } => AuthoritativeTextGenerationOutcomeRef::Rejected {
                conversation_id: *conversation_id,
                taskrun_id: *taskrun_id,
                attempt_id: *attempt_id,
                conversation_stream_version: *conversation_stream_version,
                taskrun_stream_version: *taskrun_stream_version,
                user_message,
                reserved_assistant_message_id: *reserved_assistant_message_id,
                reason: *reason,
            },
            Self::ProhibitedInputRejected {
                conversation_id,
                taskrun_id,
                attempt_id,
                conversation_stream_version,
                taskrun_stream_version,
                user_message,
                reserved_assistant_message_id,
                reason,
            } => AuthoritativeTextGenerationOutcomeRef::ProhibitedInputRejected {
                conversation_id: *conversation_id,
                taskrun_id: *taskrun_id,
                attempt_id: *attempt_id,
                conversation_stream_version: *conversation_stream_version,
                taskrun_stream_version: *taskrun_stream_version,
                user_message,
                reserved_assistant_message_id: *reserved_assistant_message_id,
                reason: *reason,
            },
        }
    }
}
