use runne_api::{
    WorkspaceFileContent, WorkspaceFileHostError, WorkspaceFileListRequest, WorkspaceFilePage,
    WorkspaceFileReadRequest,
};

/// Runtime-owned provider for bounded Workspace file projections.
pub trait WorkspaceFileProvider: Clone + Send + Sync + 'static {
    fn list_files(
        &self,
        principal: &str,
        request: &WorkspaceFileListRequest,
    ) -> Result<WorkspaceFilePage, WorkspaceFileHostError>;
    fn read_file(
        &self,
        principal: &str,
        request: &WorkspaceFileReadRequest,
    ) -> Result<WorkspaceFileContent, WorkspaceFileHostError>;
}
