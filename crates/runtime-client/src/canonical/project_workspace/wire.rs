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
pub(super) struct RootBindingWire<'a> {
    pub expected_version: u64,
    pub root_admission: &'a gocode_api::ProtectedRootBindTransport,
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
pub(super) fn project_page(
    value: ProjectPageWire,
    limit: u16,
    principal: &gocode_api::ApiPrincipalId,
) -> Result<ProjectPageDto, RuntimeApiError> {
    if value.items.len() > usize::from(limit)
        || (value.next_cursor.0.is_some() && value.items.len() != usize::from(limit))
    {
        return invalid();
    }
    let items = value
        .items
        .into_iter()
        .map(ProjectSnapshotDto::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let next = value.next_cursor.0.map(project_cursor).transpose()?;
    if let Some(cursor) = next.as_ref() {
        let cursor = gocode_api::ProjectPageCursor::decode_token(cursor.as_str())
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        let item = items
            .last()
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        let item_id = item
            .id()
            .to_string()
            .parse()
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        (cursor.parts_for_principal(principal).ok() == Some(item_id))
            .then_some(())
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
    }
    Ok(ProjectPageDto { items, next })
}
pub(super) fn workspace_page(
    value: WorkspacePageWire,
    limit: u16,
    principal: &gocode_api::ApiPrincipalId,
    project_id: CanonicalId,
) -> Result<WorkspacePageDto, RuntimeApiError> {
    if value.items.len() > usize::from(limit)
        || (value.next_cursor.0.is_some() && value.items.len() != usize::from(limit))
    {
        return invalid();
    }
    let items = value
        .items
        .into_iter()
        .map(WorkspaceSnapshotDto::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let next = value.next_cursor.0.map(workspace_cursor).transpose()?;
    if let Some(cursor) = next.as_ref() {
        let cursor = gocode_api::WorkspacePageCursor::decode_token(cursor.as_str())
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        let item = items
            .last()
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        let project = project_id
            .to_string()
            .parse()
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        let item_id = item
            .id()
            .to_string()
            .parse()
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
        (cursor.parts_for_principal(principal, project).ok() == Some(item_id))
            .then_some(())
            .ok_or_else(|| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))?;
    }
    Ok(WorkspacePageDto { items, next })
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
    gocode_api::ProjectPageCursor::decode_token(&value)
        .map(|_| ProjectPageCursor(value))
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
fn workspace_cursor(value: String) -> Result<WorkspacePageCursor, RuntimeApiError> {
    gocode_api::WorkspacePageCursor::decode_token(&value)
        .map(|_| WorkspacePageCursor(value))
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
fn invalid<T>() -> Result<T, RuntimeApiError> {
    Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}
