use super::{
    CanonicalId, ConversationCreated, ConversationMessage, ConversationTextResult,
    ProjectCommandAcknowledgement, WorkspaceCommandAcknowledgement,
};

/// Closed result of one authoritative reconciliation observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandReconciliationDisposition {
    NotCommittedRetryable,
    Indeterminate,
    DurablyRecorded(CommandReconciliationOutcome),
}

/// Closed durable result correlated to the original command witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandReconciliationOutcome {
    ProjectCreated(ProjectCommandAcknowledgement),
    ProjectArchived(ProjectCommandAcknowledgement),
    ProjectDeleted(ProjectCommandAcknowledgement),
    WorkspaceCreated(WorkspaceCommandAcknowledgement),
    WorkspaceRootBound(WorkspaceCommandAcknowledgement),
    WorkspaceOpened(WorkspaceCommandAcknowledgement),
    ConversationCreated(ConversationCreated),
    ConversationTextCompleted(Box<ConversationTextResult>),
    ConversationTextRejected(Box<ConversationTextRejection>),
    ConversationTextProhibitedInputRejected(Box<ConversationTextRejection>),
}

impl CommandReconciliationDisposition {
    #[must_use]
    pub const fn not_committed_retryable() -> Self {
        Self::NotCommittedRetryable
    }

    #[must_use]
    pub const fn indeterminate() -> Self {
        Self::Indeterminate
    }
}

/// Closed non-sensitive generation failure reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationGenerationFailureReason {
    ProviderOutputRejected,
}

/// Durable rejected generation. No assistant message is fabricated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationTextRejection {
    pub conversation_id: CanonicalId,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub conversation_stream_version: u64,
    pub task_run_stream_version: u64,
    pub user_message: ConversationMessage,
    pub reserved_assistant_message_id: CanonicalId,
    pub reason: ConversationGenerationFailureReason,
}
