use serde::{Deserialize, Serialize};

use super::{
    ProjectCommandAcknowledgement, ProjectPageCursor, ProjectPageDto, ProjectSnapshotDto,
    WorkspaceCommandAcknowledgement, WorkspacePageCursor, WorkspacePageDto, WorkspaceSnapshotDto,
};
use crate::canonical::{CanonicalId, RuntimeApiError, RuntimeApiErrorKind};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateProjectWire {
    pub project_id: CanonicalId,
    pub display_name: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateWorkspaceWire {
    pub workspace_id: CanonicalId,
    pub display_name: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExistingWire {
    pub expected_version: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RootBindingWire {
    pub expected_version: u64,
    pub root_admission: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProjectWire {
    project_id: CanonicalId,
    display_name: String,
    version: u64,
    archived: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkspaceWire {
    workspace_id: CanonicalId,
    project_id: CanonicalId,
    display_name: String,
    version: u64,
    open: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProjectAckWire {
    project_id: CanonicalId,
    new_version: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkspaceAckWire {
    workspace_id: CanonicalId,
    new_version: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProjectPageWire {
    items: Vec<ProjectWire>,
    next_cursor: RequiredNullableToken,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkspacePageWire {
    items: Vec<WorkspaceWire>,
    next_cursor: RequiredNullableToken,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct RequiredNullableToken(Option<String>);

impl TryFrom<ProjectWire> for ProjectSnapshotDto {
    type Error = RuntimeApiError;
    fn try_from(value: ProjectWire) -> Result<Self, Self::Error> {
        name(&value.display_name)?;
        version(value.version)?;
        Ok(Self {
            id: value.project_id,
            name: value.display_name,
            version: value.version,
            archived: value.archived,
        })
    }
}
impl TryFrom<WorkspaceWire> for WorkspaceSnapshotDto {
    type Error = RuntimeApiError;
    fn try_from(value: WorkspaceWire) -> Result<Self, Self::Error> {
        name(&value.display_name)?;
        version(value.version)?;
        Ok(Self {
            id: value.workspace_id,
            project_id: value.project_id,
            name: value.display_name,
            version: value.version,
            open: value.open,
        })
    }
}
impl TryFrom<ProjectAckWire> for ProjectCommandAcknowledgement {
    type Error = RuntimeApiError;
    fn try_from(value: ProjectAckWire) -> Result<Self, Self::Error> {
        version(value.new_version)?;
        Ok(Self {
            id: value.project_id,
            version: value.new_version,
        })
    }
}
impl TryFrom<WorkspaceAckWire> for WorkspaceCommandAcknowledgement {
    type Error = RuntimeApiError;
    fn try_from(value: WorkspaceAckWire) -> Result<Self, Self::Error> {
        version(value.new_version)?;
        Ok(Self {
            id: value.workspace_id,
            version: value.new_version,
        })
    }
}
impl TryFrom<ProjectPageWire> for ProjectPageDto {
    type Error = RuntimeApiError;
    fn try_from(value: ProjectPageWire) -> Result<Self, Self::Error> {
        if value.items.len() > 100 {
            return invalid();
        }
        let items = value
            .items
            .into_iter()
            .map(ProjectSnapshotDto::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let next = value.next_cursor.0.map(project_cursor).transpose()?;
        Ok(Self { items, next })
    }
}
impl TryFrom<WorkspacePageWire> for WorkspacePageDto {
    type Error = RuntimeApiError;
    fn try_from(value: WorkspacePageWire) -> Result<Self, Self::Error> {
        if value.items.len() > 100 {
            return invalid();
        }
        let items = value
            .items
            .into_iter()
            .map(WorkspaceSnapshotDto::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let next = value.next_cursor.0.map(workspace_cursor).transpose()?;
        Ok(Self { items, next })
    }
}

fn version(value: u64) -> Result<(), RuntimeApiError> {
    (value != 0)
        .then_some(())
        .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
fn name(value: &str) -> Result<(), RuntimeApiError> {
    gocode_api::ProjectWorkspaceDisplayNameInput::new(value.to_owned())
        .map(|_| ())
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
fn project_cursor(value: String) -> Result<ProjectPageCursor, RuntimeApiError> {
    cursor(&value, "gocode-project-page-v1.", 119)
        .then_some(ProjectPageCursor(value))
        .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
fn workspace_cursor(value: String) -> Result<WorkspacePageCursor, RuntimeApiError> {
    cursor(&value, "gocode-workspace-page-v1.", 153)
        .then_some(WorkspacePageCursor(value))
        .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
fn cursor(value: &str, prefix: &str, length: usize) -> bool {
    value.len() == length
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn invalid<T>() -> Result<T, RuntimeApiError> {
    Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
