use super::CanonicalId;
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReconciliationResponse {
    NotCommittedRetryable,
    Indeterminate,
    DurablyRecorded { outcome: OutcomeWire },
}

#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum OutcomeWire {
    CreateProject {
        project_id: CanonicalId,
        new_version: u64,
    },
    ArchiveProject {
        project_id: CanonicalId,
        new_version: u64,
    },
    DeleteProject {
        project_id: CanonicalId,
        new_version: u64,
    },
    RenameProject {
        project_id: CanonicalId,
        new_version: u64,
    },
    CreateWorkspace {
        workspace_id: CanonicalId,
        new_version: u64,
    },
    BindWorkspaceRoot {
        workspace_id: CanonicalId,
        new_version: u64,
    },
    OpenWorkspace {
        workspace_id: CanonicalId,
        new_version: u64,
    },
    CreateConversation {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        stream_version: u64,
        committed_at: u64,
    },
    GenerateConversationText {
        terminal: TextTerminalKind,
        conversation_id: CanonicalId,
        task_run_id: CanonicalId,
        attempt_id: CanonicalId,
        conversation_stream_version: u64,
        task_run_stream_version: u64,
        user_message: MessageWire,
        #[serde(default)]
        assistant_message: StrictOptional<Box<MessageWire>>,
        #[serde(default)]
        reserved_assistant_message_id: StrictOptional<CanonicalId>,
        #[serde(default)]
        reason: StrictOptional<FailureReasonWire>,
    },
    CancelTaskRun {
        task_run_id: CanonicalId,
        new_version: u64,
    },
    SubmitTaskRun {
        task_run_id: CanonicalId,
        new_version: u64,
    },
    ApprovalDecision {
        approval_id: CanonicalId,
        new_version: u64,
        task_run_id: CanonicalId,
        state: ApprovalStateWire,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ApprovalStateWire {
    Approved,
    Denied,
    Expired,
    Cancelled,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TextTerminalKind {
    Completed,
    Rejected,
    ProhibitedInputRejected,
}

pub(super) struct TextTerminalWire {
    pub terminal: TextTerminalKind,
    pub conversation_id: CanonicalId,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub conversation_stream_version: u64,
    pub task_run_stream_version: u64,
    pub user_message: MessageWire,
    pub assistant_message: StrictOptional<Box<MessageWire>>,
    pub reserved_assistant_message_id: StrictOptional<CanonicalId>,
    pub reason: StrictOptional<FailureReasonWire>,
}

pub(super) struct StrictOptional<T>(Option<T>);

impl<T> Default for StrictOptional<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> StrictOptional<T> {
    pub(super) fn into_option(self) -> Option<T> {
        self.0
    }
    pub(super) const fn is_present(&self) -> bool {
        self.0.is_some()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for StrictOptional<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FailureReasonWire {
    ProviderOutputRejected,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MessageWire {
    pub message_id: CanonicalId,
    pub role: MessageRoleWire,
    pub task_run_id: CanonicalId,
    pub attempt_id: CanonicalId,
    pub text: String,
    pub committed_at: u64,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum MessageRoleWire {
    User,
    Assistant,
}
