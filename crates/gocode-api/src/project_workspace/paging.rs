use super::{ProjectSnapshot, ProjectWorkspaceHostError, WorkspaceSnapshot};
use gocode_domain::id::{ProjectId, WorkspaceId};

/// Maximum number of snapshots a single Project/Workspace page may expose.
pub const MAX_PROJECT_WORKSPACE_PAGE_SIZE: u16 = 100;

/// Closed, validated size shared by API, application ports, and store adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectWorkspacePageSize(u16);

impl ProjectWorkspacePageSize {
    /// Validates a nonzero page size no larger than the public maximum.
    pub fn new(value: u16) -> Result<Self, ProjectWorkspaceHostError> {
        if value == 0 || value > MAX_PROJECT_WORKSPACE_PAGE_SIZE {
            return Err(ProjectWorkspaceHostError::Conflict);
        }
        Ok(Self(value))
    }

    /// Returns the already validated size.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Opaque cursor for a stable Project page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectPageCursor(ProjectId);

/// Opaque cursor for a stable Workspace page, bound to its Project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspacePageCursor {
    project_id: ProjectId,
    workspace_id: WorkspaceId,
}

/// Closed, bounded page request for Projects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPageRequest {
    size: ProjectWorkspacePageSize,
    cursor: Option<ProjectPageCursor>,
}

impl ProjectPageRequest {
    /// Creates a page request with a strict nonzero upper bound.
    pub fn new(
        limit: u16,
        cursor: Option<ProjectPageCursor>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        Ok(Self {
            size: ProjectWorkspacePageSize::new(limit)?,
            cursor,
        })
    }

    /// Returns validated page components for a repository adapter.
    pub fn parts(&self) -> (ProjectWorkspacePageSize, Option<ProjectId>) {
        (self.size, self.cursor.map(|cursor| cursor.0))
    }
}

/// Closed, bounded page request for Workspaces of one exact Project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePageRequest {
    size: ProjectWorkspacePageSize,
    cursor: Option<WorkspacePageCursor>,
}

impl WorkspacePageRequest {
    /// Creates a page request with a strict nonzero upper bound.
    pub fn new(
        limit: u16,
        cursor: Option<WorkspacePageCursor>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        Ok(Self {
            size: ProjectWorkspacePageSize::new(limit)?,
            cursor,
        })
    }

    /// Returns validated components only for the exact requested Project.
    pub fn parts_for(
        &self,
        project_id: ProjectId,
    ) -> Result<(ProjectWorkspacePageSize, Option<WorkspaceId>), ProjectWorkspaceHostError> {
        match self.cursor {
            Some(cursor) if cursor.project_id != project_id => {
                Err(ProjectWorkspaceHostError::NotFound)
            }
            Some(cursor) => Ok((self.size, Some(cursor.workspace_id))),
            None => Ok((self.size, None)),
        }
    }
}

/// Bounded Project page with an opaque exclusive continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPage {
    items: Vec<ProjectSnapshot>,
    next_cursor: Option<ProjectPageCursor>,
}

impl ProjectPage {
    /// Forms a page after enforcing its exact requested bound and cursor shape.
    pub fn new(
        size: ProjectWorkspacePageSize,
        items: Vec<ProjectSnapshot>,
        next_cursor: Option<ProjectId>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        let coherent_cursor = match next_cursor {
            Some(cursor) => {
                items.len() == usize::from(size.get())
                    && items.last().map(|item| item.project_id) == Some(cursor)
            }
            None => true,
        };
        if items.len() > usize::from(size.get()) || !coherent_cursor {
            return Err(ProjectWorkspaceHostError::InvariantViolation);
        }
        Ok(Self {
            items,
            next_cursor: next_cursor.map(ProjectPageCursor),
        })
    }

    /// Returns immutable page items.
    pub fn items(&self) -> &[ProjectSnapshot] {
        &self.items
    }

    /// Returns the opaque exclusive continuation cursor.
    pub const fn next_cursor(&self) -> Option<ProjectPageCursor> {
        self.next_cursor
    }
}

/// Bounded Workspace page with an opaque Project-bound continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePage {
    items: Vec<WorkspaceSnapshot>,
    next_cursor: Option<WorkspacePageCursor>,
}

impl WorkspacePage {
    /// Forms a page after enforcing its exact bound, Project, and cursor shape.
    pub fn new(
        size: ProjectWorkspacePageSize,
        project_id: ProjectId,
        items: Vec<WorkspaceSnapshot>,
        next_cursor: Option<WorkspaceId>,
    ) -> Result<Self, ProjectWorkspaceHostError> {
        let project_matches = items.iter().all(|item| item.project_id == project_id);
        let coherent_cursor = match next_cursor {
            Some(cursor) => {
                items.len() == usize::from(size.get())
                    && items.last().map(|item| item.workspace_id) == Some(cursor)
            }
            None => true,
        };
        if items.len() > usize::from(size.get()) || !project_matches || !coherent_cursor {
            return Err(ProjectWorkspaceHostError::InvariantViolation);
        }
        Ok(Self {
            items,
            next_cursor: next_cursor.map(|workspace_id| WorkspacePageCursor {
                project_id,
                workspace_id,
            }),
        })
    }

    /// Returns immutable page items.
    pub fn items(&self) -> &[WorkspaceSnapshot] {
        &self.items
    }

    /// Returns the opaque Project-bound continuation cursor.
    pub const fn next_cursor(&self) -> Option<WorkspacePageCursor> {
        self.next_cursor
    }
}
