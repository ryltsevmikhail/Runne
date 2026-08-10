//! Closed versioned encoding for durable Project/Workspace success receipts.

use super::primitives::*;
use super::{StoreCodec, StoreCodecError};
use gocode_domain::id::{ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};

const MAX_REHYDRATED_VERSION: u64 = 1_000_000;

/// Original successful value retained for exact idempotent replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectWorkspaceReceipt {
    /// Project mutation result.
    Project(Project),
    /// Workspace mutation result.
    Workspace(Workspace),
    /// Project deletion acknowledgement.
    ProjectDeleted {
        /// Deleted aggregate identity.
        project_id: ProjectId,
        /// Version after deletion.
        new_version: u64,
    },
}

/// Strict codec for Project/Workspace receipts.
pub struct ProjectWorkspaceReceiptCodec;

impl StoreCodec<ProjectWorkspaceReceipt> for ProjectWorkspaceReceiptCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &ProjectWorkspaceReceipt) -> Result<Vec<u8>, StoreCodecError> {
        let mut bytes = Vec::with_capacity(64);
        write_u16_be(&mut bytes, Self::CODEC_VERSION);
        match value {
            ProjectWorkspaceReceipt::Project(project) => {
                bytes.push(1);
                write_uuid(&mut bytes, project.id().as_bytes());
                write_u64_be(&mut bytes, project.version());
                bytes.push(u8::from(project.archived()));
                write_name(&mut bytes, project.display_name())?;
            }
            ProjectWorkspaceReceipt::Workspace(workspace) => {
                bytes.push(2);
                write_uuid(&mut bytes, workspace.id().as_bytes());
                write_uuid(&mut bytes, workspace.project_id().as_bytes());
                write_u64_be(&mut bytes, workspace.version());
                bytes.push(u8::from(workspace.open_state()));
                write_name(&mut bytes, workspace.display_name())?;
            }
            ProjectWorkspaceReceipt::ProjectDeleted {
                project_id,
                new_version,
            } => {
                bytes.push(3);
                write_uuid(&mut bytes, project_id.as_bytes());
                write_u64_be(&mut bytes, *new_version);
            }
        }
        Ok(bytes)
    }

    fn decode(&self, bytes: &[u8]) -> Result<ProjectWorkspaceReceipt, StoreCodecError> {
        let mut position = 0;
        let version = read_u16_be(bytes, &mut position)?;
        if version != Self::CODEC_VERSION {
            return Err(StoreCodecError::UnsupportedVersion {
                found: version,
                supported: Self::CODEC_VERSION,
            });
        }
        let tag = *bytes.get(position).ok_or(StoreCodecError::Truncated)?;
        position += 1;
        let receipt = match tag {
            1 => decode_project(bytes, &mut position)?,
            2 => decode_workspace(bytes, &mut position)?,
            3 => ProjectWorkspaceReceipt::ProjectDeleted {
                project_id: ProjectId::from_bytes(read_uuid(bytes, &mut position)?),
                new_version: valid_version(read_u64_be(bytes, &mut position)?)?,
            },
            tag => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "ProjectWorkspaceReceipt",
                });
            }
        };
        if position != bytes.len() {
            return Err(StoreCodecError::TrailingBytes {
                remaining: bytes.len() - position,
            });
        }
        Ok(receipt)
    }
}

fn write_name(bytes: &mut Vec<u8>, value: &str) -> Result<(), StoreCodecError> {
    if value.len() > 256 {
        return Err(StoreCodecError::Oversized {
            field: "project_workspace_display_name",
            max: 256,
            actual: value.len(),
        });
    }
    write_len_prefixed(bytes, value.as_bytes());
    Ok(())
}

fn read_name(bytes: &[u8], position: &mut usize) -> Result<String, StoreCodecError> {
    let value = read_len_prefixed(bytes, position)?;
    if value.len() > 256 {
        return Err(StoreCodecError::Oversized {
            field: "project_workspace_display_name",
            max: 256,
            actual: value.len(),
        });
    }
    String::from_utf8(value.to_vec()).map_err(|_| StoreCodecError::InvalidValue {
        context: "ProjectWorkspace display name UTF-8",
    })
}

fn valid_version(version: u64) -> Result<u64, StoreCodecError> {
    if version == 0 || version > MAX_REHYDRATED_VERSION {
        return Err(StoreCodecError::InvalidValue {
            context: "ProjectWorkspace version",
        });
    }
    Ok(version)
}

fn decode_project(
    bytes: &[u8],
    position: &mut usize,
) -> Result<ProjectWorkspaceReceipt, StoreCodecError> {
    let id = ProjectId::from_bytes(read_uuid(bytes, position)?);
    let version = valid_version(read_u64_be(bytes, position)?)?;
    let archived = read_bool(bytes, position)?;
    let name = ProjectWorkspaceDisplayName::new(read_name(bytes, position)?).map_err(|_| {
        StoreCodecError::InvalidValue {
            context: "Project display name",
        }
    })?;
    let mut project = Project::create(id, name);
    for _ in 1..version {
        if project.archived() {
            project.restore()
        } else {
            project.archive()
        }
        .map_err(|_| StoreCodecError::InvalidValue {
            context: "Project receipt state",
        })?;
    }
    if project.archived() != archived {
        return Err(StoreCodecError::InvalidValue {
            context: "Project receipt lifecycle",
        });
    }
    Ok(ProjectWorkspaceReceipt::Project(project))
}

fn decode_workspace(
    bytes: &[u8],
    position: &mut usize,
) -> Result<ProjectWorkspaceReceipt, StoreCodecError> {
    let id = WorkspaceId::from_bytes(read_uuid(bytes, position)?);
    let project_id = ProjectId::from_bytes(read_uuid(bytes, position)?);
    let version = valid_version(read_u64_be(bytes, position)?)?;
    let open = read_bool(bytes, position)?;
    let name = ProjectWorkspaceDisplayName::new(read_name(bytes, position)?).map_err(|_| {
        StoreCodecError::InvalidValue {
            context: "Workspace display name",
        }
    })?;
    let mut workspace = Workspace::create(id, project_id, name);
    if open {
        if version == 1 {
            return Err(StoreCodecError::InvalidValue {
                context: "Workspace receipt lifecycle",
            });
        }
        workspace
            .open()
            .map_err(|_| StoreCodecError::InvalidValue {
                context: "Workspace receipt state",
            })?;
    }
    let applied = 1 + u64::from(open);
    for _ in applied..version {
        workspace
            .bind_root()
            .map_err(|_| StoreCodecError::InvalidValue {
                context: "Workspace receipt state",
            })?;
    }
    Ok(ProjectWorkspaceReceipt::Workspace(workspace))
}

fn read_bool(bytes: &[u8], position: &mut usize) -> Result<bool, StoreCodecError> {
    let value = *bytes.get(*position).ok_or(StoreCodecError::Truncated)?;
    *position += 1;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreCodecError::InvalidValue {
            context: "ProjectWorkspace boolean",
        }),
    }
}
