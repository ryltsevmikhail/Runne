use runne_api::{EditorLaunchReceipt, OpenEditorRequest, WorkspaceEditorHostError};

/// Runtime-owned provider for one explicit scoped editor activation.
pub trait WorkspaceEditorProvider: Clone + Send + Sync + 'static {
    /// Activates the native editor for an admitted Workspace-relative file.
    fn open_editor(
        &self,
        principal: &str,
        request: &OpenEditorRequest,
    ) -> Result<EditorLaunchReceipt, WorkspaceEditorHostError>;
}
