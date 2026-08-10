use gocode_domain::id::ProjectId;
use gocode_domain::project_workspace::{Project, Workspace};

/// Closed storage failures for Project and Workspace authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectWorkspaceRepositoryError { NotFound, Conflict, Forbidden, Unavailable, InvariantViolation }

/// Principal-bound, versioned repository for canonical Project and Workspace state.
pub trait ProjectWorkspaceRepository: Clone + Send + Sync + 'static {
    fn create_project(&self, principal: &str, command_id: CommandId, key: &IdempotencyKey, project: Project) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn archive_project(&self, principal: &str, command_id: CommandId, key: &IdempotencyKey, id: ProjectId, expected_version: u64) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn restore_project(&self, principal: &str, command_id: CommandId, key: &IdempotencyKey, id: ProjectId, expected_version: u64) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn delete_project(&self, principal: &str, command_id: CommandId, key: &IdempotencyKey, id: ProjectId, expected_version: u64) -> Result<u64, ProjectWorkspaceRepositoryError>;
    fn create_workspace(&self, principal: &str, command_id: CommandId, key: &IdempotencyKey, workspace: Workspace) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
    fn open_workspace(&self, principal: &str, command_id: CommandId, key: &IdempotencyKey, id: WorkspaceId, expected_version: u64) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
    fn bind_workspace_root(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        expected_version: u64,
        admission_digest: &[u8; 32],
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
    fn list_projects(&self, principal: &str) -> Result<Vec<Project>, ProjectWorkspaceRepositoryError>;
    fn get_project(&self, principal: &str, id: ProjectId) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn list_workspaces(&self, principal: &str, project_id: ProjectId) -> Result<Vec<Workspace>, ProjectWorkspaceRepositoryError>;
    fn get_workspace(&self, principal: &str, id: WorkspaceId) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
}
