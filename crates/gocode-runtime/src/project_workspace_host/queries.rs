use super::{RuntimeProjectWorkspaceHost, commands::map_error};
use gocode_api::{
    ProjectQueryContext, ProjectSnapshot, ProjectWorkspaceHostError, ProjectWorkspaceQueryHostPort,
    WorkspaceSnapshot,
};
use gocode_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionVerifier,
};
use gocode_domain::id::{ProjectId, WorkspaceId};

impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    ProjectWorkspaceQueryHostPort for RuntimeProjectWorkspaceHost<R, C, V>
{
    async fn list_projects(
        &self,
        context: ProjectQueryContext,
    ) -> Result<Vec<ProjectSnapshot>, ProjectWorkspaceHostError> {
        self.service.list_projects(context).map_err(map_error)
    }
    async fn get_project(
        &self,
        context: ProjectQueryContext,
        id: ProjectId,
    ) -> Result<ProjectSnapshot, ProjectWorkspaceHostError> {
        self.service.get_project(context, id).map_err(map_error)
    }
    async fn list_workspaces(
        &self,
        context: ProjectQueryContext,
        id: ProjectId,
    ) -> Result<Vec<WorkspaceSnapshot>, ProjectWorkspaceHostError> {
        self.service.list_workspaces(context, id).map_err(map_error)
    }
    async fn get_workspace(
        &self,
        context: ProjectQueryContext,
        id: WorkspaceId,
    ) -> Result<WorkspaceSnapshot, ProjectWorkspaceHostError> {
        self.service.get_workspace(context, id).map_err(map_error)
    }
}
