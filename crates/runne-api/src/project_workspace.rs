//! Transport-neutral canonical Project and Workspace host contracts.

use crate::{ApiActor, ApiPrincipalId, RootHandleAdmission};
use runne_domain::{
    id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::ProjectWorkspaceDisplayName,
};
mod paging;
pub use paging::*;
mod cursor;
pub use cursor::*;

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

    /// Returns the validated display name without consuming its boundary type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
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
