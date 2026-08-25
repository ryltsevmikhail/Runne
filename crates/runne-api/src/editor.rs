//! Runtime-owned scoped external-editor activation contracts.

use crate::{ProcessCommandContext, WorkspaceId};
use std::future::Future;

/// Capability required before a client may request editor activation.
pub const WORKSPACE_EDITOR_CAPABILITY_V1: &str = "workspace.editor.open.v1";

/// The only target selected by the renderer. The native backend resolves it
/// to the operating system's default editor without accepting executable or
/// argument material from the client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorLaunchTargetV1 {
    SystemDefault,
}

/// One explicitly requested, workspace-scoped editor activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenEditorRequest {
    workspace_id: WorkspaceId,
    relative_path: String,
    target: EditorLaunchTargetV1,
}

impl OpenEditorRequest {
    /// Validates a non-empty relative file reference.
    pub fn new(
        workspace_id: WorkspaceId,
        relative_path: impl Into<String>,
        target: EditorLaunchTargetV1,
    ) -> Result<Self, WorkspaceEditorHostError> {
        let relative_path = relative_path.into();
        validate_relative_path(&relative_path)?;
        Ok(Self {
            workspace_id,
            relative_path,
            target,
        })
    }

    /// Returns the authoritative Workspace identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the bounded relative file reference.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns the closed target selector.
    #[must_use]
    pub const fn target(&self) -> EditorLaunchTargetV1 {
        self.target
    }
}

/// Result after the native backend accepted the explicit editor action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditorLaunchReceipt {
    workspace_id: WorkspaceId,
    target: EditorLaunchTargetV1,
}

impl EditorLaunchReceipt {
    /// Creates a receipt for a validated request.
    #[must_use]
    pub const fn accepted(request: &OpenEditorRequest) -> Self {
        Self {
            workspace_id: request.workspace_id,
            target: request.target,
        }
    }

    /// Returns the Workspace affected by the action.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Returns the target selected for the action.
    #[must_use]
    pub const fn target(&self) -> EditorLaunchTargetV1 {
        self.target
    }
}

/// Closed failures for editor activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceEditorHostError {
    InvalidPath,
    NotFound,
    Forbidden,
    Conflict,
    Backpressure,
    Unavailable,
    InvariantViolation,
}

fn validate_relative_path(value: &str) -> Result<(), WorkspaceEditorHostError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte == 0 || byte < 0x20)
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(WorkspaceEditorHostError::InvalidPath);
    }
    Ok(())
}

/// Runtime-owned native editor action boundary.
pub trait WorkspaceEditorHostPort: Send + Sync {
    /// Performs one explicit, authorized editor activation.
    fn open_editor(
        &self,
        context: ProcessCommandContext,
        request: OpenEditorRequest,
    ) -> impl Future<Output = Result<EditorLaunchReceipt, WorkspaceEditorHostError>> + Send;
}
