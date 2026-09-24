use super::codec::{self, VERSION};
use crate::{BoundedCanonicalId, SecurityStateError};

mod approval;
pub use approval::ApprovalDecisionKind;

#[derive(Clone, Eq, PartialEq)]
pub enum NormalizedMutationCommand {
    CreateProject {
        project_id: BoundedCanonicalId,
        display_name: String,
    },
    RenameProject {
        project_id: BoundedCanonicalId,
        expected_version: u64,
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
    SubmitTaskRun {
        conversation_id: BoundedCanonicalId,
        workspace_id: BoundedCanonicalId,
        prompt: String,
    },
    /// Historical promptless submit command decoded from tag 12.
    /// New commands must use `SubmitTaskRun` with a required prompt.
    LegacySubmitTaskRun {
        conversation_id: BoundedCanonicalId,
        workspace_id: BoundedCanonicalId,
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

impl std::fmt::Debug for NormalizedMutationCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NormalizedMutationCommand(<redacted>)")
    }
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
            Self::RenameProject {
                project_id,
                expected_version,
                display_name,
            } => {
                value.push(11);
                codec::put_id(&mut value, project_id)?;
                put_version(&mut value, *expected_version)?;
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
            Self::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt,
            } => {
                value.extend([13]);
                codec::put_id(&mut value, conversation_id)?;
                codec::put_id(&mut value, workspace_id)?;
                codec::put_message_text(&mut value, prompt)?;
            }
            Self::LegacySubmitTaskRun {
                conversation_id,
                workspace_id,
            } => {
                value.extend([12]);
                codec::put_id(&mut value, conversation_id)?;
                codec::put_id(&mut value, workspace_id)?;
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

include!("command/decode.rs");
