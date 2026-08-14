use gocode_api::{
    AuthoritativeCommandOutcome, AuthoritativeCommandOutcomeRef,
    AuthoritativeTextGenerationOutcomeRef, CanonicalConversationMessage, ConversationTextResult,
};
use serde::Serialize;
#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub(super) enum ReconciliationResponse<'a> {
    NotCommittedRetryable,
    Indeterminate,
    DurablyRecorded { outcome: Box<OutcomeWire<'a>> },
}
#[derive(Serialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(super) enum OutcomeWire<'a> {
    CreateProject {
        project_id: String,
        new_version: u64,
    },
    ArchiveProject {
        project_id: String,
        new_version: u64,
    },
    DeleteProject {
        project_id: String,
        new_version: u64,
    },
    CreateWorkspace {
        workspace_id: String,
        new_version: u64,
    },
    BindWorkspaceRoot {
        workspace_id: String,
        new_version: u64,
    },
    OpenWorkspace {
        workspace_id: String,
        new_version: u64,
    },
    CreateConversation {
        conversation_id: String,
        workspace_id: String,
        stream_version: u64,
        committed_at: i64,
    },
    GenerateConversationText {
        #[serde(flatten)]
        terminal: Box<TextTerminalWire<'a>>,
    },
}
#[derive(Serialize)]
#[serde(tag = "terminal", rename_all = "snake_case")]
pub(super) enum TextTerminalWire<'a> {
    Completed {
        #[serde(flatten)]
        result: CompletedWire<'a>,
    },
    Rejected {
        #[serde(flatten)]
        rejection: RejectionWire<'a>,
    },
    ProhibitedInputRejected {
        #[serde(flatten)]
        rejection: RejectionWire<'a>,
    },
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CompletedWire<'a> {
    conversation_id: String,
    task_run_id: String,
    attempt_id: String,
    conversation_stream_version: u64,
    task_run_stream_version: u64,
    user_message: MessageWire<'a>,
    assistant_message: MessageWire<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RejectionWire<'a> {
    conversation_id: String,
    task_run_id: String,
    attempt_id: String,
    conversation_stream_version: u64,
    task_run_stream_version: u64,
    user_message: MessageWire<'a>,
    reserved_assistant_message_id: String,
    reason: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageWire<'a> {
    message_id: String,
    role: &'static str,
    task_run_id: String,
    attempt_id: String,
    text: &'a str,
    committed_at: i64,
}
pub(super) fn durable(value: &AuthoritativeCommandOutcome) -> Option<OutcomeWire<'_>> {
    Some(match value.view() {
        AuthoritativeCommandOutcomeRef::ProjectCreated(v) => OutcomeWire::CreateProject {
            project_id: v.project_id.to_string(),
            new_version: v.new_version,
        },
        AuthoritativeCommandOutcomeRef::ProjectArchived(v) => OutcomeWire::ArchiveProject {
            project_id: v.project_id.to_string(),
            new_version: v.new_version,
        },
        AuthoritativeCommandOutcomeRef::ProjectDeleted(v) => OutcomeWire::DeleteProject {
            project_id: v.project_id.to_string(),
            new_version: v.new_version,
        },
        AuthoritativeCommandOutcomeRef::WorkspaceCreated(v) => OutcomeWire::CreateWorkspace {
            workspace_id: v.workspace_id.to_string(),
            new_version: v.new_version,
        },
        AuthoritativeCommandOutcomeRef::WorkspaceRootBound(v) => OutcomeWire::BindWorkspaceRoot {
            workspace_id: v.workspace_id.to_string(),
            new_version: v.new_version,
        },
        AuthoritativeCommandOutcomeRef::WorkspaceOpened(v) => OutcomeWire::OpenWorkspace {
            workspace_id: v.workspace_id.to_string(),
            new_version: v.new_version,
        },
        AuthoritativeCommandOutcomeRef::ConversationCreated(v) => OutcomeWire::CreateConversation {
            conversation_id: v.conversation_id.to_string(),
            workspace_id: v.workspace_id.to_string(),
            stream_version: v.stream_version,
            committed_at: v.committed_at.as_i64(),
        },
        AuthoritativeCommandOutcomeRef::ConversationText(value) => {
            OutcomeWire::GenerateConversationText {
                terminal: Box::new(text_terminal(value)),
            }
        }
    })
}

fn text_terminal(value: AuthoritativeTextGenerationOutcomeRef<'_>) -> TextTerminalWire<'_> {
    match value {
        AuthoritativeTextGenerationOutcomeRef::Completed(value) => TextTerminalWire::Completed {
            result: completed(value),
        },
        AuthoritativeTextGenerationOutcomeRef::Rejected {
            conversation_id,
            taskrun_id,
            attempt_id,
            conversation_stream_version,
            taskrun_stream_version,
            user_message,
            reserved_assistant_message_id,
            reason,
        } => TextTerminalWire::Rejected {
            rejection: RejectionWire {
                conversation_id: conversation_id.to_string(),
                task_run_id: taskrun_id.to_string(),
                attempt_id: attempt_id.to_string(),
                conversation_stream_version,
                task_run_stream_version: taskrun_stream_version,
                user_message: message(user_message),
                reserved_assistant_message_id: reserved_assistant_message_id.to_string(),
                reason: reason.as_code(),
            },
        },
        AuthoritativeTextGenerationOutcomeRef::ProhibitedInputRejected {
            conversation_id,
            taskrun_id,
            attempt_id,
            conversation_stream_version,
            taskrun_stream_version,
            user_message,
            reserved_assistant_message_id,
            reason,
        } => TextTerminalWire::ProhibitedInputRejected {
            rejection: RejectionWire {
                conversation_id: conversation_id.to_string(),
                task_run_id: taskrun_id.to_string(),
                attempt_id: attempt_id.to_string(),
                conversation_stream_version,
                task_run_stream_version: taskrun_stream_version,
                user_message: message(user_message),
                reserved_assistant_message_id: reserved_assistant_message_id.to_string(),
                reason: reason.as_code(),
            },
        },
    }
}

fn completed(value: &ConversationTextResult) -> CompletedWire<'_> {
    CompletedWire {
        conversation_id: value.conversation_id.to_string(),
        task_run_id: value.taskrun_id.to_string(),
        attempt_id: value.attempt_id.to_string(),
        conversation_stream_version: value.conversation_stream_version,
        task_run_stream_version: value.taskrun_stream_version,
        user_message: message(&value.user_message),
        assistant_message: message(&value.assistant_message),
    }
}

fn message(value: &CanonicalConversationMessage) -> MessageWire<'_> {
    MessageWire {
        message_id: value.message_id.to_string(),
        role: value.role.as_str(),
        task_run_id: value.taskrun_id.to_string(),
        attempt_id: value.attempt_id.to_string(),
        text: &value.text,
        committed_at: value.committed_at.as_i64(),
    }
}
