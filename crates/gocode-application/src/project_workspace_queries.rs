impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    ProjectWorkspaceService<R, C, V>
{
    pub fn list_projects(
        &self,
        context: ProjectQueryContext,
        request: ProjectPageRequest,
    ) -> Result<ProjectPage, ProjectWorkspaceServiceError> {
        let (limit, after) = request
            .parts_for_principal(&context.principal)
            .map_err(|_| ProjectWorkspaceServiceError::NotFound)?;
        self.repository
            .list_projects(context.principal.as_str(), limit, after)
            .map_err(map_error)
            .and_then(|(items, cursor)| {
                ProjectPage::new(
                    limit,
                    context.principal,
                    items.into_iter().map(project_snapshot).collect(),
                    cursor,
                )
                .map_err(|_| ProjectWorkspaceServiceError::InvariantViolation)
            })
    }

    pub fn get_project(
        &self,
        context: ProjectQueryContext,
        id: gocode_domain::id::ProjectId,
    ) -> Result<ProjectSnapshot, ProjectWorkspaceServiceError> {
        self.repository
            .get_project(context.principal.as_str(), id)
            .map_err(map_error)
            .map(project_snapshot)
    }

    pub fn list_workspaces(
        &self,
        context: ProjectQueryContext,
        id: gocode_domain::id::ProjectId,
        request: WorkspacePageRequest,
    ) -> Result<WorkspacePage, ProjectWorkspaceServiceError> {
        let (limit, after) = request
            .parts_for_principal(&context.principal, id)
            .map_err(|_| ProjectWorkspaceServiceError::NotFound)?;
        self.repository
            .list_workspaces(context.principal.as_str(), id, limit, after)
            .map_err(map_error)
            .and_then(|(items, cursor)| {
                WorkspacePage::new(
                    limit,
                    context.principal,
                    id,
                    items.into_iter().map(workspace_snapshot).collect(),
                    cursor,
                )
                .map_err(|_| ProjectWorkspaceServiceError::InvariantViolation)
            })
    }

    pub fn get_workspace(
        &self,
        context: ProjectQueryContext,
        id: gocode_domain::id::WorkspaceId,
    ) -> Result<WorkspaceSnapshot, ProjectWorkspaceServiceError> {
        self.repository
            .get_workspace(context.principal.as_str(), id)
            .map_err(map_error)
            .map(workspace_snapshot)
    }
}
