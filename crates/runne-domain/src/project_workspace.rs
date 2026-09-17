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
            || value.chars().any(is_disallowed_display_name_character)
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

fn is_disallowed_display_name_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
                | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}'
        )
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

    /// Rehydrates a previously validated authoritative Project projection.
    pub fn rehydrate(
        id: ProjectId,
        display_name: ProjectWorkspaceDisplayName,
        version: u64,
        archived: bool,
    ) -> Result<Self, ProjectWorkspaceError> {
        if version == 0 || (archived && version == 1) {
            return Err(ProjectWorkspaceError::InvalidTransition);
        }
        Ok(Self {
            id,
            display_name,
            version,
            archived,
        })
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

    /// Changes the renderer-visible Project name and advances its version.
    pub fn rename(
        &mut self,
        display_name: ProjectWorkspaceDisplayName,
    ) -> Result<(), ProjectWorkspaceError> {
        if self.archived || self.display_name == display_name {
            return Err(ProjectWorkspaceError::InvalidTransition);
        }
        self.display_name = display_name;
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
    /// A Project display name was changed.
    ProjectRenamed { project_id: ProjectId },
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
