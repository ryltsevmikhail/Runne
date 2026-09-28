//! Transactional, owned metadata used by the Project Trust control surface.

use runne_application::ports::ProjectWorkspaceRepositoryError as Error;
use runne_domain::id::{ProjectId, WorkspaceId};
use rusqlite::{OptionalExtension, params};

use super::ProjectWorkspaceStore;

/// Safe canonical metadata only; it contains no native path or root identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedWorkspaceTrustMetadata {
    pub project_id: ProjectId,
    pub project_name: String,
    pub project_version: u64,
    pub workspace_id: WorkspaceId,
    pub workspace_name: String,
    pub workspace_version: u64,
}

impl ProjectWorkspaceStore {
    /// Holds the canonical writer through owned/live/open validation and the
    /// bounded operation, preserving trust-sidecar -> canonical -> root order.
    pub fn with_owned_workspace_trust_metadata<T>(
        &self,
        principal: &str,
        project: ProjectId,
        workspace: WorkspaceId,
        operation: impl FnOnce(OwnedWorkspaceTrustMetadata) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.store
            .with_project_workspace_transaction(|transaction| {
                let metadata: Option<(String, i64, String, i64)> = transaction
                    .query_row(
                        "SELECT p.display_name, p.version, w.display_name, w.version
                     FROM projects p JOIN workspaces w ON w.project_id = p.project_id
                     WHERE p.project_id = ?1 AND p.principal_id = ?2 AND p.archived = 0
                       AND w.workspace_id = ?3 AND w.principal_id = ?2
                       AND w.live = 1 AND w.open = 1",
                        params![project.as_bytes(), principal, workspace.as_bytes()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()
                    .map_err(|_| Error::Unavailable)?;
                let Some((project_name, project_version, workspace_name, workspace_version)) =
                    metadata
                else {
                    return Err(Error::NotFound);
                };
                operation(OwnedWorkspaceTrustMetadata {
                    project_id: project,
                    project_name,
                    project_version: u64::try_from(project_version)
                        .map_err(|_| Error::InvariantViolation)?,
                    workspace_id: workspace,
                    workspace_name,
                    workspace_version: u64::try_from(workspace_version)
                        .map_err(|_| Error::InvariantViolation)?,
                })
            })
    }
}
