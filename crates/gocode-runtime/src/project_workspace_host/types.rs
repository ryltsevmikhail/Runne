use gocode_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionVerifier,
};
use gocode_application::project_workspace_service::ProjectWorkspaceService;

/// Runtime composition root for principal-bound Project and Workspace ports.
pub struct RuntimeProjectWorkspaceHost<R, C, V> {
    pub(crate) service: ProjectWorkspaceService<R, C, V>,
}

impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    RuntimeProjectWorkspaceHost<R, C, V>
{
    /// Creates a host over the runtime's authoritative repository adapter.
    pub fn new(repository: R, current_admission: C, admission_verifier: V) -> Self {
        Self {
            service: ProjectWorkspaceService::new(
                repository,
                current_admission,
                admission_verifier,
            ),
        }
    }
}
