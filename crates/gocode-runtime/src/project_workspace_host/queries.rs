use super::{RuntimeProjectWorkspaceHost, types::WorkItem};
use gocode_api::{
    ProjectPage, ProjectPageRequest, ProjectQueryContext, ProjectSnapshot,
    ProjectWorkspaceHostError, ProjectWorkspaceQueryHostPort, WorkspacePage, WorkspacePageRequest,
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
        request: ProjectPageRequest,
    ) -> Result<ProjectPage, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::ListProjects(context, request, reply))
            .await
    }
    async fn get_project(
        &self,
        context: ProjectQueryContext,
        id: ProjectId,
    ) -> Result<ProjectSnapshot, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::GetProject(context, id, reply))
            .await
    }
    async fn list_workspaces(
        &self,
        context: ProjectQueryContext,
        id: ProjectId,
        request: WorkspacePageRequest,
    ) -> Result<WorkspacePage, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::ListWorkspaces(context, id, request, reply))
            .await
    }
    async fn get_workspace(
        &self,
        context: ProjectQueryContext,
        id: WorkspaceId,
    ) -> Result<WorkspaceSnapshot, ProjectWorkspaceHostError> {
        self.submit(|reply| WorkItem::GetWorkspace(context, id, reply))
            .await
    }
}
