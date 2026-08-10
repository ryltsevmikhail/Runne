//! Canonical Project and Workspace aggregate state.

use crate::id::{ProjectId, WorkspaceId};

/// Maximum UTF-8 byte length of a Project or Workspace display name.
pub const MAX_PROJECT_WORKSPACE_DISPLAY_NAME_BYTES: usize = 256;

/// Closed domain rejection for Project and Workspace state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectWorkspaceError {
    /// A display name is empty, oversized, or contains a control character.
    InvalidDisplayName,
    /// The requested lifecycle transition is not allowed.
    InvalidTransition,
}

/// Validated renderer-visible name. It never represents a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectWorkspaceDisplayName(String);

impl ProjectWorkspaceDisplayName {
    /// Validates a canonical display name.
    pub fn new(value: String) -> Result<Self, ProjectWorkspaceError> {
        if value.is_empty()
            || value.len() > MAX_PROJECT_WORKSPACE_DISPLAY_NAME_BYTES
            || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ProjectWorkspaceError::InvalidDisplayName);
        }
        Ok(Self(value))
    }

    /// Returns the validated display name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical Project aggregate projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    id: ProjectId,
    display_name: ProjectWorkspaceDisplayName,
    version: u64,
    archived: bool,
}

impl Project {
    /// Creates the initial Project state.
    pub fn create(id: ProjectId, display_name: ProjectWorkspaceDisplayName) -> Self {
        Self {
            id,
            display_name,
            version: 1,
            archived: false,
        }
    }

    /// Marks the Project archived and advances its version.
    pub fn archive(&mut self) -> Result<(), ProjectWorkspaceError> {
        if self.archived {
            return Err(ProjectWorkspaceError::InvalidTransition);
        }
        self.archived = true;
        self.version = self
            .version
            .checked_add(1)
            .ok_or(ProjectWorkspaceError::InvalidTransition)?;
        Ok(())
    }

    /// Restores an archived Project and advances its version.
    pub fn restore(&mut self) -> Result<(), ProjectWorkspaceError> {
        if !self.archived {
            return Err(ProjectWorkspaceError::InvalidTransition);
        }
        self.archived = false;
        self.version = self
            .version
            .checked_add(1)
            .ok_or(ProjectWorkspaceError::InvalidTransition)?;
        Ok(())
    }

    /// Returns the aggregate identity.
    pub const fn id(&self) -> ProjectId {
        self.id
    }
    /// Returns the display name.
    pub fn display_name(&self) -> &str {
        self.display_name.as_str()
    }
    /// Returns the committed version.
    pub const fn version(&self) -> u64 {
        self.version
    }
    /// Returns whether the Project is archived.
    pub const fn archived(&self) -> bool {
        self.archived
    }
}

/// Canonical Workspace aggregate projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    id: WorkspaceId,
    project_id: ProjectId,
    display_name: ProjectWorkspaceDisplayName,
    version: u64,
    open: bool,
}

impl Workspace {
    /// Creates a closed Workspace owned by a Project.
    pub fn create(
        id: WorkspaceId,
        project_id: ProjectId,
        display_name: ProjectWorkspaceDisplayName,
    ) -> Self {
        Self {
            id,
            project_id,
            display_name,
            version: 1,
            open: false,
        }
    }

    /// Opens this Workspace and advances its version.
    pub fn open(&mut self) -> Result<(), ProjectWorkspaceError> {
        if self.open {
            return Err(ProjectWorkspaceError::InvalidTransition);
        }
        self.open = true;
        self.version = self
            .version
            .checked_add(1)
            .ok_or(ProjectWorkspaceError::InvalidTransition)?;
        Ok(())
    }

    /// Advances the version after an accepted root binding.
    pub fn bind_root(&mut self) -> Result<(), ProjectWorkspaceError> {
        self.version = self
            .version
            .checked_add(1)
            .ok_or(ProjectWorkspaceError::InvalidTransition)?;
        Ok(())
    }

    /// Returns the aggregate identity.
    pub const fn id(&self) -> WorkspaceId {
        self.id
    }
    /// Returns the owning Project identity.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }
    /// Returns the display name.
    pub fn display_name(&self) -> &str {
        self.display_name.as_str()
    }
    /// Returns the committed version.
    pub const fn version(&self) -> u64 {
        self.version
    }
    /// Returns whether the Workspace is open.
    pub const fn open_state(&self) -> bool {
        self.open
    }
}

/// Closed domain events for Project and Workspace lifecycle changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectWorkspaceEvent {
    /// A Project was created.
    ProjectCreated { project_id: ProjectId },
    /// A Project was archived.
    ProjectArchived { project_id: ProjectId },
    /// A Project was restored.
    ProjectRestored { project_id: ProjectId },
    /// A Project was deleted.
    ProjectDeleted { project_id: ProjectId },
    /// A Workspace was created.
    WorkspaceCreated {
        workspace_id: WorkspaceId,
        project_id: ProjectId,
    },
    /// A Workspace was opened.
    WorkspaceOpened { workspace_id: WorkspaceId },
    /// A verified native root was bound without retaining root material.
    WorkspaceRootBound { workspace_id: WorkspaceId },
}
