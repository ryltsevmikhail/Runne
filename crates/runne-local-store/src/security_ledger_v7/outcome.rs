use super::codec::{self, VERSION};
use super::outcome_generation::{
    generation, message, put_versions, terminal_tag, validate, version,
};
use crate::{BoundedCanonicalId, SecurityStateError};

mod approval;
pub use approval::ApprovalOutcomeState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMutationOutcome {
    ProjectCreate {
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
}

impl CanonicalMutationOutcome {
    /// # Errors
    ///
    /// Returns an error for a zero authoritative version.
    pub fn project(
        project_id: BoundedCanonicalId,
        new_version: u64,
    ) -> Result<Self, SecurityStateError> {
        valid_version(new_version)?;
        Ok(Self::ProjectCreate {
            project_id,
            new_version,
        })
    }
    /// # Errors
    ///
    /// Returns an error when an outcome violates its closed encoding.
    pub fn encode(&self) -> Result<Vec<u8>, SecurityStateError> {
        let mut value = vec![VERSION];
        match self {
            Self::ProjectCreate {
                project_id,
                new_version,
            } => simple(&mut value, 1, project_id, *new_version)?,
            Self::ProjectArchive {
                project_id,
                new_version,
            } => simple(&mut value, 2, project_id, *new_version)?,
            Self::ProjectDelete {
                project_id,
                new_version,
            } => simple(&mut value, 3, project_id, *new_version)?,
            Self::WorkspaceCreate {
                workspace_id,
                new_version,
            } => simple(&mut value, 4, workspace_id, *new_version)?,
            Self::WorkspaceBindRoot {
                workspace_id,
                new_version,
            } => simple(&mut value, 5, workspace_id, *new_version)?,
            Self::WorkspaceOpen {
                workspace_id,
                new_version,
            } => simple(&mut value, 6, workspace_id, *new_version)?,
            Self::ConversationCreate {
                conversation_id,
                workspace_id,
                stream_version,
                committed_at,
            } => {
                value.push(7);
                codec::put_id(&mut value, conversation_id)?;
                codec::put_id(&mut value, workspace_id)?;
                put_versions(&mut value, &[*stream_version, *committed_at])?;
            }
            Self::Generation {
                terminal,
                conversation_id,
                task_run_id,
                attempt_id,
                conversation_stream_version,
                task_run_stream_version,
                user_message,
                assistant,
            } => {
                validate(*terminal, task_run_id, attempt_id, user_message, assistant)?;
                value.extend([8, terminal_tag(*terminal)]);
                codec::put_id(&mut value, conversation_id)?;
                codec::put_id(&mut value, task_run_id)?;
                codec::put_id(&mut value, attempt_id)?;
                put_versions(
                    &mut value,
                    &[*conversation_stream_version, *task_run_stream_version],
                )?;
                message(&mut value, user_message)?;
                match &**assistant {
                    GenerationAssistant::Completed(message_value) => {
                        value.push(1);
                        message(&mut value, message_value)?;
                    }
                    GenerationAssistant::Rejected {
                        reserved_message_id,
                        reason,
                    } => {
                        value.push(2);
                        codec::put_id(&mut value, reserved_message_id)?;
                        value.push(reason.tag());
                    }
                }
            }
            Self::TaskRunCancellationRequested {
                task_run_id,
                new_version,
            } => {
                simple(&mut value, 9, task_run_id, *new_version)?;
            }
            Self::ApprovalRespond {
                approval_id,
                new_version,
                state,
            } => approval::encode(&mut value, approval_id, *new_version, *state)?,
        }
        Ok(value)
    }
    /// # Errors
    ///
    /// Returns an error for malformed, unknown, or trailing wire data.
    pub fn decode(value: &[u8]) -> Result<Self, SecurityStateError> {
        let mut input = value;
        if codec::byte(&mut input)? != VERSION {
            return Err(SecurityStateError::InvalidTransition);
        }
        let outcome = match codec::byte(&mut input)? {
            1 => project(&mut input, 1)?,
            2 => project(&mut input, 2)?,
            3 => project(&mut input, 3)?,
            4 => workspace(&mut input, 4)?,
            5 => workspace(&mut input, 5)?,
            6 => workspace(&mut input, 6)?,
            7 => Self::ConversationCreate {
                conversation_id: codec::id(&mut input)?,
                workspace_id: codec::id(&mut input)?,
                stream_version: version(&mut input)?,
                committed_at: version(&mut input)?,
            },
            8 => generation(&mut input)?,
            9 => Self::TaskRunCancellationRequested {
                task_run_id: codec::id(&mut input)?,
                new_version: version(&mut input)?,
            },
            10 => approval::decode(&mut input)?,
            _ => return Err(SecurityStateError::InvalidTransition),
        };
        codec::finish(input)?;
        outcome.encode()?;
        Ok(outcome)
    }
}

impl GenerationFailureReason {
    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::ProviderOutputRejected => 1,
        }
    }

    pub(super) const fn from_tag(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ProviderOutputRejected),
            _ => None,
        }
    }
}
fn simple(
    output: &mut Vec<u8>,
    tag: u8,
    id: &BoundedCanonicalId,
    version_value: u64,
) -> Result<(), SecurityStateError> {
    output.push(tag);
    codec::put_id(output, id)?;
    valid_version(version_value)?;
    output.extend(version_value.to_be_bytes());
    Ok(())
}
fn project(input: &mut &[u8], tag: u8) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let id = codec::id(input)?;
    let new_version = version(input)?;
    Ok(match tag {
        1 => CanonicalMutationOutcome::ProjectCreate {
            project_id: id,
            new_version,
        },
        2 => CanonicalMutationOutcome::ProjectArchive {
            project_id: id,
            new_version,
        },
        _ => CanonicalMutationOutcome::ProjectDelete {
            project_id: id,
            new_version,
        },
    })
}
fn workspace(input: &mut &[u8], tag: u8) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let id = codec::id(input)?;
    let new_version = version(input)?;
    Ok(match tag {
        4 => CanonicalMutationOutcome::WorkspaceCreate {
            workspace_id: id,
            new_version,
        },
        5 => CanonicalMutationOutcome::WorkspaceBindRoot {
            workspace_id: id,
            new_version,
        },
        _ => CanonicalMutationOutcome::WorkspaceOpen {
            workspace_id: id,
            new_version,
        },
    })
}
fn valid_version(value: u64) -> Result<u64, SecurityStateError> {
    (value != 0)
        .then_some(value)
        .ok_or(SecurityStateError::InvalidTransition)
}
