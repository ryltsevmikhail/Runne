//! Transport-neutral canonical Project and Workspace host contracts.

use crate::{ApiActor, ApiPrincipalId, RootHandleAdmission};
use gocode_domain::{
    id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::ProjectWorkspaceDisplayName,
};

/// Maximum number of snapshots a single Project/Workspace page may expose.
pub const MAX_PROJECT_WORKSPACE_PAGE_SIZE: u16 = 100;

/// Bounded, validated display name accepted at the host transport boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectWorkspaceDisplayNameInput(ProjectWorkspaceDisplayName);

impl ProjectWorkspaceDisplayNameInput {
    /// Validates a renderer-visible name before it reaches a host command.
    pub fn new(value: String) -> Result<Self, ProjectWorkspaceHostError> {
        ProjectWorkspaceDisplayName::new(value)
            .map(Self)
            .map_err(|_| ProjectWorkspaceHostError::Conflict)
    }

    /// Consumes the validated input for the canonical domain aggregate.
    pub fn into_domain(self) -> ProjectWorkspaceDisplayName {
        self.0
    }
}

/// Opaque cursor for a stable Project page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectPageCursor(ProjectId);

/// Opaque cursor for a stable Workspace page, bound to its Project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspacePageCursor {
    project_id: ProjectId,
    workspace_id: WorkspaceId,
}

/// Closed, bounded page request for Projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPageRequest {
    limit: u16,
    cursor: Option<ProjectPageCursor>,
}

impl ProjectPageRequest {
    /// Creates a page request with a strict nonzero upper bound.
    pub fn new(
        limit: u16,
        cursor: Option<ProjectPageCursor>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        if limit == 0 || limit > MAX_PROJECT_WORKSPACE_PAGE_SIZE {
            return Err(ProjectWorkspaceHostError::Conflict);
        }
        Ok(Self { limit, cursor })
    }

    /// Returns validated page components for a repository adapter.
    pub fn parts(&self) -> (u16, Option<ProjectId>) {
        (self.limit, self.cursor.map(|cursor| cursor.0))
    }
}

/// Closed, bounded page request for Workspaces of one exact Project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePageRequest {
    limit: u16,
    cursor: Option<WorkspacePageCursor>,
}

impl WorkspacePageRequest {
    /// Creates a page request with a strict nonzero upper bound.
    pub fn new(
        limit: u16,
        cursor: Option<WorkspacePageCursor>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        if limit == 0 || limit > MAX_PROJECT_WORKSPACE_PAGE_SIZE {
            return Err(ProjectWorkspaceHostError::Conflict);
        }
        Ok(Self { limit, cursor })
    }

    /// Returns validated components only for the exact requested Project.
    pub fn parts_for(
        &self,
        project_id: ProjectId,
    ) -> Result<(u16, Option<WorkspaceId>), ProjectWorkspaceHostError> {
        match self.cursor {
            Some(cursor) if cursor.project_id != project_id => {
                Err(ProjectWorkspaceHostError::NotFound)
            }
            Some(cursor) => Ok((self.limit, Some(cursor.workspace_id))),
            None => Ok((self.limit, None)),
        }
    }
}

/// Authenticated context carried by every Project or Workspace mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCommandContext {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub principal: ApiPrincipalId,
    pub actor: ApiActor,
}

/// Authenticated context carried by Project and Workspace reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectQueryContext {
    pub principal: ApiPrincipalId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingProjectCommand {
    pub project_id: ProjectId,
    pub expected_version: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingWorkspaceCommand {
    pub workspace_id: WorkspaceId,
    pub expected_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateProjectCommand {
    pub project_id: ProjectId,
    pub display_name: ProjectWorkspaceDisplayNameInput,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceCommand {
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub display_name: ProjectWorkspaceDisplayNameInput,
}
#[derive(Debug)]
pub struct BindWorkspaceRootCommand {
    pub workspace_id: WorkspaceId,
    pub expected_version: u64,
    pub root_admission: RootHandleAdmission,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCommandAck {
    pub project_id: ProjectId,
    pub new_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCommandAck {
    pub workspace_id: WorkspaceId,
    pub new_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSnapshot {
    pub project_id: ProjectId,
    pub display_name: String,
    pub version: u64,
    pub archived: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSnapshot {
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub display_name: String,
    pub version: u64,
    pub open: bool,
}

/// Bounded Project page with an opaque exclusive continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPage {
    pub items: Vec<ProjectSnapshot>,
    pub next_cursor: Option<ProjectPageCursor>,
}

impl ProjectPage {
    /// Forms a page after enforcing the public page bound.
    pub fn new(
        items: Vec<ProjectSnapshot>,
        next_cursor: Option<ProjectId>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        if items.len() > usize::from(MAX_PROJECT_WORKSPACE_PAGE_SIZE) {
            return Err(ProjectWorkspaceHostError::InvariantViolation);
        }
        Ok(Self {
            items,
            next_cursor: next_cursor.map(ProjectPageCursor),
        })
    }
}

/// Bounded Workspace page with an opaque Project-bound continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePage {
    pub items: Vec<WorkspaceSnapshot>,
    pub next_cursor: Option<WorkspacePageCursor>,
}

impl WorkspacePage {
    /// Forms a page after enforcing the public page bound.
    pub fn new(
        project_id: ProjectId,
        items: Vec<WorkspaceSnapshot>,
        next_cursor: Option<WorkspaceId>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        if items.len() > usize::from(MAX_PROJECT_WORKSPACE_PAGE_SIZE) {
            return Err(ProjectWorkspaceHostError::InvariantViolation);
        }
        Ok(Self {
            items,
            next_cursor: next_cursor.map(|workspace_id| WorkspacePageCursor {
                project_id,
                workspace_id,
            }),
        })
    }
}

/// Closed, redacted failures from the canonical Project and Workspace host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectWorkspaceHostError {
    NotFound,
    Conflict,
    Forbidden,
    Backpressure,
    Unavailable,
    InvariantViolation,
}

pub trait ProjectWorkspaceCommandHostPort: Send + Sync {
    fn create_project(
        &self,
        context: ProjectCommandContext,
        command: CreateProjectCommand,
    ) -> impl std::future::Future<Output = Result<ProjectCommandAck, ProjectWorkspaceHostError>> + Send;
    fn archive_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> impl std::future::Future<Output = Result<ProjectCommandAck, ProjectWorkspaceHostError>> + Send;
    fn restore_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> impl std::future::Future<Output = Result<ProjectCommandAck, ProjectWorkspaceHostError>> + Send;
    fn delete_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> impl std::future::Future<Output = Result<ProjectCommandAck, ProjectWorkspaceHostError>> + Send;
    fn create_workspace(
        &self,
        context: ProjectCommandContext,
        command: CreateWorkspaceCommand,
    ) -> impl std::future::Future<Output = Result<WorkspaceCommandAck, ProjectWorkspaceHostError>> + Send;
    fn open_workspace(
        &self,
        context: ProjectCommandContext,
        command: ExistingWorkspaceCommand,
    ) -> impl std::future::Future<Output = Result<WorkspaceCommandAck, ProjectWorkspaceHostError>> + Send;
    fn bind_workspace_root(
        &self,
        context: ProjectCommandContext,
        command: BindWorkspaceRootCommand,
    ) -> impl std::future::Future<Output = Result<WorkspaceCommandAck, ProjectWorkspaceHostError>> + Send;
}

pub trait ProjectWorkspaceQueryHostPort: Send + Sync {
    fn list_projects(
        &self,
        context: ProjectQueryContext,
        request: ProjectPageRequest,
    ) -> impl std::future::Future<Output = Result<ProjectPage, ProjectWorkspaceHostError>> + Send;
    fn get_project(
        &self,
        context: ProjectQueryContext,
        id: ProjectId,
    ) -> impl std::future::Future<Output = Result<ProjectSnapshot, ProjectWorkspaceHostError>> + Send;
    fn list_workspaces(
        &self,
        context: ProjectQueryContext,
        id: ProjectId,
        request: WorkspacePageRequest,
    ) -> impl std::future::Future<Output = Result<WorkspacePage, ProjectWorkspaceHostError>> + Send;
    fn get_workspace(
        &self,
        context: ProjectQueryContext,
        id: WorkspaceId,
    ) -> impl std::future::Future<Output = Result<WorkspaceSnapshot, ProjectWorkspaceHostError>> + Send;
}
