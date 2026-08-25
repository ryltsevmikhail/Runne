//! Query and host-port contracts for Workspace changes and diffs.

use crate::workspace_diff::{WorkspaceChangeSet, WorkspaceDiff, validate_path};
use crate::{ApiPrincipalId, WorkspaceId};
use std::future::Future;

pub const MAX_WORKSPACE_CHANGE_PAGE_SIZE: u16 = 200;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceChangeListRequest {
    workspace_id: WorkspaceId,
    limit: u16,
}

impl WorkspaceChangeListRequest {
    pub fn new(workspace_id: WorkspaceId, limit: u16) -> Result<Self, WorkspaceDiffHostError> {
        if limit == 0 || limit > MAX_WORKSPACE_CHANGE_PAGE_SIZE {
            return Err(WorkspaceDiffHostError::InvalidLimit);
        }
        Ok(Self {
            workspace_id,
            limit,
        })
    }
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffReadRequest {
    workspace_id: WorkspaceId,
    relative_path: String,
}

impl WorkspaceDiffReadRequest {
    pub fn new(
        workspace_id: WorkspaceId,
        relative_path: impl Into<String>,
    ) -> Result<Self, WorkspaceDiffHostError> {
        Ok(Self {
            workspace_id,
            relative_path: validate_path(relative_path.into())
                .map_err(|_| WorkspaceDiffHostError::InvalidPath)?,
        })
    }
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffQueryContext {
    pub principal: ApiPrincipalId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceDiffHostError {
    InvalidPath,
    InvalidLimit,
    NotFound,
    Forbidden,
    Conflict,
    SizeLimit,
    BinaryContent,
    Backpressure,
    Unavailable,
    InvariantViolation,
}

pub trait WorkspaceDiffHostPort: Send + Sync {
    fn list_changes(
        &self,
        context: WorkspaceDiffQueryContext,
        request: WorkspaceChangeListRequest,
    ) -> impl Future<Output = Result<WorkspaceChangeSet, WorkspaceDiffHostError>> + Send;
    fn read_diff(
        &self,
        context: WorkspaceDiffQueryContext,
        request: WorkspaceDiffReadRequest,
    ) -> impl Future<Output = Result<WorkspaceDiff, WorkspaceDiffHostError>> + Send;
}
