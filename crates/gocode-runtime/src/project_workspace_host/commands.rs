use super::RuntimeProjectWorkspaceHost;
use gocode_api::{
    BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand, ExistingProjectCommand,
    ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceHostError, WorkspaceCommandAck,
};
use gocode_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionVerifier,
};
use gocode_application::project_workspace_service::ProjectWorkspaceServiceError;

impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    ProjectWorkspaceCommandHostPort for RuntimeProjectWorkspaceHost<R, C, V>
{
    async fn create_project(
        &self,
        context: ProjectCommandContext,
        command: CreateProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.service
            .create_project(context, command)
            .map_err(map_error)
    }
    async fn archive_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.service
            .archive_project(context, command)
            .map_err(map_error)
    }
    async fn restore_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.service
            .restore_project(context, command)
            .map_err(map_error)
    }
    async fn delete_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.service
            .delete_project(context, command)
            .map_err(map_error)
    }
    async fn create_workspace(
        &self,
        context: ProjectCommandContext,
        command: CreateWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.service
            .create_workspace(context, command)
            .map_err(map_error)
    }
    async fn open_workspace(
        &self,
        context: ProjectCommandContext,
        command: ExistingWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.service
            .open_workspace(context, command)
            .map_err(map_error)
    }
    async fn bind_workspace_root(
        &self,
        context: ProjectCommandContext,
        command: BindWorkspaceRootCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.service
            .bind_workspace_root(context, command)
            .map_err(map_error)
    }
}

pub(super) fn map_error(error: ProjectWorkspaceServiceError) -> ProjectWorkspaceHostError {
    match error {
        ProjectWorkspaceServiceError::NotFound => ProjectWorkspaceHostError::NotFound,
        ProjectWorkspaceServiceError::Conflict => ProjectWorkspaceHostError::Conflict,
        ProjectWorkspaceServiceError::Forbidden => ProjectWorkspaceHostError::Forbidden,
        ProjectWorkspaceServiceError::Unavailable => ProjectWorkspaceHostError::Unavailable,
        ProjectWorkspaceServiceError::InvariantViolation => {
            ProjectWorkspaceHostError::InvariantViolation
        }
    }
}
