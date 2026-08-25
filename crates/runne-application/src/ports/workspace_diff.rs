use runne_api::{
    WorkspaceChangeListRequest, WorkspaceChangeSet, WorkspaceDiff, WorkspaceDiffHostError,
    WorkspaceDiffReadRequest,
};

/// Runtime-owned provider for bounded Workspace change projections.
pub trait WorkspaceDiffProvider: Clone + Send + Sync + 'static {
    fn list_changes(
        &self,
        principal: &str,
        request: &WorkspaceChangeListRequest,
    ) -> Result<WorkspaceChangeSet, WorkspaceDiffHostError>;
    fn read_diff(
        &self,
        principal: &str,
        request: &WorkspaceDiffReadRequest,
    ) -> Result<WorkspaceDiff, WorkspaceDiffHostError>;
}
