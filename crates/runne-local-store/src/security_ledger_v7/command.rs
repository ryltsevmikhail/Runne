use super::codec::{self, VERSION};
use crate::{BoundedCanonicalId, SecurityStateError};

mod approval;
pub use approval::ApprovalDecisionKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedMutationCommand {
    CreateProject {
        project_id: BoundedCanonicalId,
        display_name: String,
    },
    ArchiveProject {
        project_id: BoundedCanonicalId,
        expected_version: u64,
    },
    DeleteProject {
        project_id: BoundedCanonicalId,
        expected_version: u64,
    },
    CreateWorkspace {
        workspace_id: BoundedCanonicalId,
        project_id: BoundedCanonicalId,
        display_name: String,
    },
    BindWorkspaceRoot {
        workspace_id: BoundedCanonicalId,
        expected_version: u64,
        admission_digest: [u8; 32],
    },
    OpenWorkspace {
        workspace_id: BoundedCanonicalId,
        expected_version: u64,
    },
    CreateConversation {
        conversation_id: BoundedCanonicalId,
        workspace_id: BoundedCanonicalId,
    },
    GenerateText {
        conversation_id: BoundedCanonicalId,
        expected_version: u64,
        text: String,
    },
    CancelTaskRun {
        task_run_id: BoundedCanonicalId,
        expected_version: u64,
    },
    ApprovalRespond {
        approval_id: BoundedCanonicalId,
        expected_version: u64,
        decision: ApprovalDecisionKind,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    },
}

impl NormalizedMutationCommand {
    /// Creates a validated project creation command.
    ///
    /// # Errors
    ///
    /// Returns an error when the display name violates the canonical bounds.
    pub fn create_project(
        project_id: BoundedCanonicalId,
        display_name: String,
    ) -> Result<Self, SecurityStateError> {
        validate_display_name(&display_name)?;
        Ok(Self::CreateProject {
            project_id,
            display_name,
        })
    }
    /// # Errors
    ///
    /// Returns an error for a zero version or admission digest.
    pub fn bind_workspace_root(
        workspace_id: BoundedCanonicalId,
        expected_version: u64,
        admission_digest: [u8; 32],
    ) -> Result<Self, SecurityStateError> {
        (expected_version != 0 && admission_digest != [0; 32])
            .then_some(Self::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                admission_digest,
            })
            .ok_or(SecurityStateError::InvalidTransition)
    }
    /// Encodes the normalized command using the versioned ledger format.
    ///
    /// # Errors
    ///
    /// Returns an error when a command field cannot be represented within the
    /// canonical ledger bounds.
    #[allow(clippy::too_many_lines)]
    pub fn encode(&self) -> Result<Vec<u8>, SecurityStateError> {
        let mut value = vec![VERSION];
        match self {
            Self::CreateProject {
                project_id,
                display_name,
            } => {
                value.push(1);
                codec::put_id(&mut value, project_id)?;
                codec::put_display_name(&mut value, display_name)?;
            }
            Self::ArchiveProject {
                project_id,
                expected_version,
            } => {
                value.push(2);
                codec::put_id(&mut value, project_id)?;
                put_version(&mut value, *expected_version)?;
            }
            Self::DeleteProject {
                project_id,
                expected_version,
            } => {
                value.push(3);
                codec::put_id(&mut value, project_id)?;
                put_version(&mut value, *expected_version)?;
            }
            Self::CreateWorkspace {
                workspace_id,
                project_id,
                display_name,
            } => {
                value.push(4);
                codec::put_id(&mut value, workspace_id)?;
                codec::put_id(&mut value, project_id)?;
                codec::put_display_name(&mut value, display_name)?;
            }
            Self::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                admission_digest,
            } => {
                value.push(5);
                codec::put_id(&mut value, workspace_id)?;
                put_version(&mut value, *expected_version)?;
                if *admission_digest == [0; 32] {
                    return Err(SecurityStateError::InvalidTransition);
                }
                value.extend(admission_digest);
            }
            Self::OpenWorkspace {
                workspace_id,
                expected_version,
            } => {
                value.push(6);
                codec::put_id(&mut value, workspace_id)?;
                put_version(&mut value, *expected_version)?;
            }
            Self::CreateConversation {
                conversation_id,
                workspace_id,
            } => {
                value.push(7);
                codec::put_id(&mut value, conversation_id)?;
                codec::put_id(&mut value, workspace_id)?;
            }
            Self::GenerateText {
                conversation_id,
                expected_version,
                text,
            } => {
                value.push(8);
                codec::put_id(&mut value, conversation_id)?;
                put_version(&mut value, *expected_version)?;
                codec::put_message_text(&mut value, text)?;
            }
            Self::CancelTaskRun {
                task_run_id,
                expected_version,
            } => {
                value.push(9);
                codec::put_id(&mut value, task_run_id)?;
                put_version(&mut value, *expected_version)?;
            }
            Self::ApprovalRespond {
                approval_id,
                expected_version,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            } => {
                value.push(10);
                approval::encode(
                    &mut value,
                    approval_id,
                    *expected_version,
                    *decision,
                    *action_digest,
                    *policy_revision,
                    *renderer_generation,
                )?;
            }
        }
        Ok(value)
    }
    /// Decodes and validates a versioned normalized command.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version/tag, malformed field, trailing
    /// bytes, or an invalid transition.
    pub fn decode(value: &[u8]) -> Result<Self, SecurityStateError> {
        let mut input = value;
        if codec::byte(&mut input)? != VERSION {
            return Err(SecurityStateError::InvalidTransition);
        }
        let command = match codec::byte(&mut input)? {
            1 => Self::create_project(codec::id(&mut input)?, codec::display_name(&mut input)?)?,
            2 => Self::ArchiveProject {
                project_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            3 => Self::DeleteProject {
                project_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            4 => Self::CreateWorkspace {
                workspace_id: codec::id(&mut input)?,
                project_id: codec::id(&mut input)?,
                display_name: codec::display_name(&mut input)?,
            },
            5 => Self::bind_workspace_root(
                codec::id(&mut input)?,
                version(&mut input)?,
                codec::fixed(&mut input)?,
            )?,
            6 => Self::OpenWorkspace {
                workspace_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            7 => Self::CreateConversation {
                conversation_id: codec::id(&mut input)?,
                workspace_id: codec::id(&mut input)?,
            },
            8 => Self::GenerateText {
                conversation_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
                text: codec::message_text(&mut input)?,
            },
            9 => Self::CancelTaskRun {
                task_run_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            10 => {
                let (
                    approval_id,
                    expected_version,
                    decision,
                    action_digest,
                    policy_revision,
                    renderer_generation,
                ) = approval::decode(&mut input)?;
                Self::ApprovalRespond {
                    approval_id,
                    expected_version,
                    decision,
                    action_digest,
                    policy_revision,
                    renderer_generation,
                }
            }
            _ => return Err(SecurityStateError::InvalidTransition),
        };
        command.encode()?;
        codec::finish(input)?;
        Ok(command)
    }
}

fn version(input: &mut &[u8]) -> Result<u64, SecurityStateError> {
    let value = codec::u64(input)?;
    (value != 0)
        .then_some(value)
        .ok_or(SecurityStateError::InvalidTransition)
}
fn put_version(output: &mut Vec<u8>, value: u64) -> Result<(), SecurityStateError> {
    (value != 0)
        .then_some(())
        .ok_or(SecurityStateError::InvalidTransition)?;
    output.extend(value.to_be_bytes());
    Ok(())
}
fn validate_display_name(value: &str) -> Result<(), SecurityStateError> {
    let mut ignored = Vec::new();
    codec::put_display_name(&mut ignored, value)
}
