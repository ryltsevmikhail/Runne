use super::codec::{self, VERSION};
use crate::{BoundedCanonicalId, MutationIdentity, MutationOperation, SecurityStateError};

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
}

impl NormalizedMutationCommand {
    /// # Errors
    ///
    /// Returns an error for an empty or oversized display name.
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
    /// # Errors
    ///
    /// Returns an error when a command field violates its closed encoding.
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
            _ => return Err(SecurityStateError::InvalidTransition),
        };
        command.encode()?;
        codec::finish(input)?;
        Ok(command)
    }
    pub(crate) fn matches_identity(&self, identity: &MutationIdentity) -> bool {
        match self {
            Self::CreateProject { project_id, .. } => {
                identity.operation() == MutationOperation::ProjectCreate
                    && identity.expected_version() == 0
                    && project_id.as_bytes() == identity.target()
            }
            Self::ArchiveProject {
                project_id,
                expected_version,
            } => {
                identity.operation() == MutationOperation::ProjectArchive
                    && *expected_version == identity.expected_version()
                    && project_id.as_bytes() == identity.target()
            }
            Self::DeleteProject {
                project_id,
                expected_version,
            } => {
                identity.operation() == MutationOperation::ProjectDelete
                    && *expected_version == identity.expected_version()
                    && project_id.as_bytes() == identity.target()
            }
            Self::CreateWorkspace { workspace_id, .. } => {
                identity.operation() == MutationOperation::WorkspaceCreate
                    && identity.expected_version() == 0
                    && workspace_id.as_bytes() == identity.target()
            }
            Self::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                ..
            } => {
                identity.operation() == MutationOperation::WorkspaceBindRoot
                    && *expected_version == identity.expected_version()
                    && workspace_id.as_bytes() == identity.target()
            }
            Self::OpenWorkspace {
                workspace_id,
                expected_version,
            } => {
                identity.operation() == MutationOperation::WorkspaceOpen
                    && *expected_version == identity.expected_version()
                    && workspace_id.as_bytes() == identity.target()
            }
            Self::CreateConversation {
                conversation_id, ..
            } => {
                identity.operation() == MutationOperation::ConversationCreate
                    && identity.expected_version() == 0
                    && conversation_id.as_bytes() == identity.target()
            }
            Self::GenerateText {
                conversation_id,
                expected_version,
                ..
            } => {
                identity.operation() == MutationOperation::ConversationGenerateText
                    && *expected_version == identity.expected_version()
                    && conversation_id.as_bytes() == identity.target()
            }
        }
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
