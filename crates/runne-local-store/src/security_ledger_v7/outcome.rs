use super::codec::{self, VERSION};
use super::outcome_generation::{
    generation, message, put_versions, terminal_tag, validate, version,
};
use crate::{BoundedCanonicalId, SecurityStateError};

mod approval;
pub use approval::ApprovalOutcomeState;
mod types;
pub use types::{
    CanonicalMutationOutcome, GenerationAssistant, GenerationFailureReason, GenerationTerminal,
    LedgerMessage, MessageRole,
};

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
            Self::ProjectCreate { .. }
            | Self::ProjectRename { .. }
            | Self::ProjectArchive { .. }
            | Self::ProjectDelete { .. } => encode_project_outcome(&mut value, self)?,
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
            } => encode_conversation_create(
                &mut value,
                conversation_id,
                workspace_id,
                *stream_version,
                *committed_at,
            )?,
            Self::Generation {
                terminal,
                conversation_id,
                task_run_id,
                attempt_id,
                conversation_stream_version,
                task_run_stream_version,
                user_message,
                assistant,
            } => encode_generation_outcome(
                &mut value,
                &GenerationEncoding {
                    terminal: *terminal,
                    conversation_id,
                    task_run_id,
                    attempt_id,
                    conversation_stream_version: *conversation_stream_version,
                    task_run_stream_version: *task_run_stream_version,
                    user_message,
                    assistant,
                },
            )?,
            Self::TaskRunCancellationRequested {
                task_run_id,
                new_version,
            } => {
                simple(&mut value, 9, task_run_id, *new_version)?;
            }
            Self::TaskRunSubmitted {
                task_run_id,
                new_version,
            } => simple(&mut value, 12, task_run_id, *new_version)?,
            Self::TaskRunUnknownSuccessorCreated {
                predecessor_task_run_id,
                successor_task_run_id,
                predecessor_version,
                successor_version,
            } => {
                encode_unknown_successor_v2(
                    &mut value,
                    predecessor_task_run_id,
                    successor_task_run_id,
                    *predecessor_version,
                    *successor_version,
                )?;
            }
            Self::TaskRunUnknownSuccessorCreatedLegacy {
                predecessor_task_run_id,
                successor_task_run_id,
                new_version,
            } => {
                encode_unknown_successor(
                    &mut value,
                    predecessor_task_run_id,
                    successor_task_run_id,
                    *new_version,
                )?;
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
            11 => project(&mut input, 11)?,
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
            12 => Self::TaskRunSubmitted {
                task_run_id: codec::id(&mut input)?,
                new_version: version(&mut input)?,
            },
            24 => decode_unknown_successor(&mut input)?,
            25 => decode_unknown_successor_v2(&mut input)?,
            10 => approval::decode(&mut input)?,
            _ => return Err(SecurityStateError::InvalidTransition),
        };
        codec::finish(input)?;
        outcome.encode()?;
        Ok(outcome)
    }
}

fn encode_project_outcome(
    value: &mut Vec<u8>,
    outcome: &CanonicalMutationOutcome,
) -> Result<(), SecurityStateError> {
    let (tag, id, version) = match outcome {
        CanonicalMutationOutcome::ProjectCreate {
            project_id,
            new_version,
        } => (1, project_id, new_version),
        CanonicalMutationOutcome::ProjectRename {
            project_id,
            new_version,
        } => (11, project_id, new_version),
        CanonicalMutationOutcome::ProjectArchive {
            project_id,
            new_version,
        } => (2, project_id, new_version),
        CanonicalMutationOutcome::ProjectDelete {
            project_id,
            new_version,
        } => (3, project_id, new_version),
        _ => return Err(SecurityStateError::InvalidTransition),
    };
    simple(value, tag, id, *version)
}

fn encode_conversation_create(
    value: &mut Vec<u8>,
    conversation_id: &BoundedCanonicalId,
    workspace_id: &BoundedCanonicalId,
    stream_version: u64,
    committed_at: u64,
) -> Result<(), SecurityStateError> {
    value.push(7);
    codec::put_id(value, conversation_id)?;
    codec::put_id(value, workspace_id)?;
    put_versions(value, &[stream_version, committed_at])
}

struct GenerationEncoding<'a> {
    terminal: GenerationTerminal,
    conversation_id: &'a BoundedCanonicalId,
    task_run_id: &'a BoundedCanonicalId,
    attempt_id: &'a BoundedCanonicalId,
    conversation_stream_version: u64,
    task_run_stream_version: u64,
    user_message: &'a LedgerMessage,
    assistant: &'a GenerationAssistant,
}

fn encode_generation_outcome(
    value: &mut Vec<u8>,
    outcome: &GenerationEncoding<'_>,
) -> Result<(), SecurityStateError> {
    validate(
        outcome.terminal,
        outcome.task_run_stream_version,
        outcome.task_run_id,
        outcome.attempt_id,
        outcome.user_message,
        outcome.assistant,
    )?;
    value.extend([8, terminal_tag(outcome.terminal)]);
    codec::put_id(value, outcome.conversation_id)?;
    codec::put_id(value, outcome.task_run_id)?;
    codec::put_id(value, outcome.attempt_id)?;
    put_versions(
        value,
        &[
            outcome.conversation_stream_version,
            outcome.task_run_stream_version,
        ],
    )?;
    message(value, outcome.user_message)?;
    match outcome.assistant {
        GenerationAssistant::Completed(message_value) => {
            value.push(1);
            message(value, message_value)?;
        }
        GenerationAssistant::Rejected {
            reserved_message_id,
            reason,
        } => {
            value.push(2);
            codec::put_id(value, reserved_message_id)?;
            value.push(reason.tag());
        }
    }
    Ok(())
}

include!("outcome/unknown_successor.rs");

include!("outcome/helpers.rs");
