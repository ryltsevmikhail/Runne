use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, Workspace};
use rusqlite::{OptionalExtension, params};

use crate::store::StoreTransaction;

use super::records::{project_from_row, workspace_from_row};

const MAX_QUERY_ITEMS: i64 = 1_000;

pub(super) fn list_projects(
    store: &StoreTransaction,
    principal: &str,
) -> Result<Vec<Project>, Error> {
    store.with_project_workspace_reader(|connection| {
        let mut statement = connection
            .prepare(
                "SELECT project_id, display_name, version, archived FROM projects
                 WHERE principal_id = ?1 ORDER BY project_id ASC LIMIT ?2",
            )
            .map_err(|_| Error::Unavailable)?;
        statement
            .query_map(params![principal, MAX_QUERY_ITEMS], project_from_row)
            .map_err(|_| Error::Unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvariantViolation)
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
) -> Result<Vec<Workspace>, Error> {
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
        let mut statement = connection
            .prepare(
                "SELECT workspace_id, project_id, display_name, version, open FROM workspaces
                 WHERE project_id = ?1 AND principal_id = ?2 AND live = 1
                 ORDER BY workspace_id ASC LIMIT ?3",
            )
            .map_err(|_| Error::Unavailable)?;
        statement
            .query_map(
                params![project_id.as_bytes(), principal, MAX_QUERY_ITEMS],
                workspace_from_row,
            )
            .map_err(|_| Error::Unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::InvariantViolation)
    })
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
