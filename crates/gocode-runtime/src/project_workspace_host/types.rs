use gocode_application::ports::ProjectWorkspaceRepository;
use gocode_application::project_workspace_service::ProjectWorkspaceService;

/// Runtime composition root for principal-bound Project and Workspace ports.
pub struct RuntimeProjectWorkspaceHost<R> {
    pub(crate) service: ProjectWorkspaceService<R>,
}

impl<R: ProjectWorkspaceRepository> RuntimeProjectWorkspaceHost<R> {
    /// Creates a host over the runtime's authoritative repository adapter.
    pub fn new(repository: R) -> Self {
        Self {
            service: ProjectWorkspaceService::new(repository),
        }
    }
}
