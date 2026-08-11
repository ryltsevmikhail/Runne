use gocode_api::ProjectWorkspacePageSize;
use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, Workspace};
use rusqlite::{OptionalExtension, params};

use crate::store::StoreTransaction;

use super::records::{project_from_row, workspace_from_row};

pub(super) fn list_projects(
    store: &StoreTransaction,
    principal: &str,
    limit: ProjectWorkspacePageSize,
    after: Option<ProjectId>,
) -> Result<(Vec<Project>, Option<ProjectId>), Error> {
    store.with_project_workspace_reader(|connection| {
        if let Some(cursor) = after {
            let valid = connection
                .query_row(
                    "SELECT 1 FROM projects WHERE project_id = ?1 AND principal_id = ?2",
                    params![cursor.as_bytes(), principal],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|_| Error::Unavailable)?
                .is_some();
            if !valid {
                return Err(Error::NotFound);
            }
        }
        let mut statement = connection
            .prepare(
                "SELECT project_id, display_name, version, archived FROM projects
                 WHERE principal_id = ?1 AND (?2 IS NULL OR project_id > ?2)
                 ORDER BY project_id ASC LIMIT ?3",
            )
            .map_err(|_| Error::Unavailable)?;
        let mut projects = statement
            .query_map(
                params![
                    principal,
                    after.map(|id| id.as_bytes().to_vec()),
                    i64::from(limit.get()) + 1,
                ],
                project_from_row,
            )
            .map_err(|_| Error::Unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvariantViolation)?;
        page(&mut projects, limit)
    })
}

pub(super) fn get_project(
    store: &StoreTransaction,
    principal: &str,
    id: ProjectId,
) -> Result<Project, Error> {
    store.with_project_workspace_reader(|connection| {
        connection
            .query_row(
                "SELECT project_id, display_name, version, archived FROM projects
                 WHERE project_id = ?1 AND principal_id = ?2",
                params![id.as_bytes(), principal],
                project_from_row,
            )
            .optional()
            .map_err(|_| Error::InvariantViolation)?
            .ok_or(Error::NotFound)
    })
}

pub(super) fn list_workspaces(
    store: &StoreTransaction,
    principal: &str,
    project_id: ProjectId,
    limit: ProjectWorkspacePageSize,
    after: Option<WorkspaceId>,
) -> Result<(Vec<Workspace>, Option<WorkspaceId>), Error> {
    store.with_project_workspace_reader(|connection| {
        let owns_project = connection
            .query_row(
                "SELECT 1 FROM projects WHERE project_id = ?1 AND principal_id = ?2",
                params![project_id.as_bytes(), principal],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| Error::Unavailable)?
            .is_some();
        if !owns_project {
            return Err(Error::NotFound);
        }
        if let Some(cursor) = after {
            let valid = connection
                .query_row(
                    "SELECT 1 FROM workspaces
                     WHERE workspace_id = ?1 AND project_id = ?2 AND principal_id = ?3 AND live = 1",
                    params![cursor.as_bytes(), project_id.as_bytes(), principal],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|_| Error::Unavailable)?
                .is_some();
            if !valid {
                return Err(Error::NotFound);
            }
        }
        let mut statement = connection
            .prepare(
                "SELECT workspace_id, project_id, display_name, version, open FROM workspaces
                 WHERE project_id = ?1 AND principal_id = ?2 AND live = 1
                   AND (?3 IS NULL OR workspace_id > ?3)
                 ORDER BY workspace_id ASC LIMIT ?4",
            )
            .map_err(|_| Error::Unavailable)?;
        let mut workspaces = statement
            .query_map(
                params![
                    project_id.as_bytes(),
                    principal,
                    after.map(|id| id.as_bytes().to_vec()),
                    i64::from(limit.get()) + 1,
                ],
                workspace_from_row,
            )
            .map_err(|_| Error::Unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvariantViolation)?;
        page(&mut workspaces, limit)
    })
}

fn page<T: PageId>(
    items: &mut Vec<T>,
    limit: ProjectWorkspacePageSize,
) -> Result<(Vec<T>, Option<T::Id>), Error> {
    let limit = usize::from(limit.get());
    let has_more = items.len() > limit;
    let cursor = if has_more {
        let index = limit.checked_sub(1).ok_or(Error::InvariantViolation)?;
        Some(items.get(index).ok_or(Error::InvariantViolation)?.page_id())
    } else {
        None
    };
    if has_more {
        items.truncate(limit);
    }
    Ok((std::mem::take(items), cursor))
}

trait PageId {
    type Id;
    fn page_id(&self) -> Self::Id;
}
impl PageId for Project {
    type Id = ProjectId;
    fn page_id(&self) -> Self::Id {
        self.id()
    }
}
impl PageId for Workspace {
    type Id = WorkspaceId;
    fn page_id(&self) -> Self::Id {
        self.id()
    }
}

pub(super) fn get_workspace(
    store: &StoreTransaction,
    principal: &str,
    id: WorkspaceId,
) -> Result<Workspace, Error> {
    store.with_project_workspace_reader(|connection| {
        connection
            .query_row(
                "SELECT workspace_id, project_id, display_name, version, open FROM workspaces
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND live = 1",
                params![id.as_bytes(), principal],
                workspace_from_row,
            )
            .optional()
            .map_err(|_| Error::InvariantViolation)?
            .ok_or(Error::NotFound)
    })
}
