use super::{RuntimeProjectWorkspaceHost, types::WorkItem};
use runne_api::{
    BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand, ExistingProjectCommand,
    ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceHostError, WorkspaceCommandAck,
};
use runne_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionVerifier,
};

impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    ProjectWorkspaceCommandHostPort for RuntimeProjectWorkspaceHost<R, C, V>
{
    async fn create_project(
        &self,
        context: ProjectCommandContext,
        command: CreateProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::CreateProject(context, command, reply))
            .await
    }
    async fn archive_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::ArchiveProject(context, command, reply))
            .await
    }
    async fn restore_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::RestoreProject(context, command, reply))
            .await
    }
    async fn delete_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::DeleteProject(context, command, reply))
            .await
    }
    async fn create_workspace(
        &self,
        context: ProjectCommandContext,
        command: CreateWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::CreateWorkspace(context, command, reply))
            .await
    }
    async fn open_workspace(
        &self,
        context: ProjectCommandContext,
        command: ExistingWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::OpenWorkspace(context, command, reply))
            .await
    }
    async fn bind_workspace_root(
        &self,
        context: ProjectCommandContext,
        command: BindWorkspaceRootCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::BindWorkspaceRoot(context, command, reply))
            .await
    }
}
