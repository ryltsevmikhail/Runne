//! Durable Project/Workspace repository sharing the authoritative SQLite writer.

use crate::store::StoreTransaction;
use runne_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error, RootAdmissionAuthorizer,
};
use runne_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use runne_domain::project_workspace::{Project, Workspace};
use rusqlite::{OptionalExtension, params};

mod approvals;
mod fingerprint;
pub(crate) mod lineage;
mod mutation_support;
mod project_mutations;
mod queries;
mod receipts;
mod reconciliation;
mod records;
mod taskrun_audit;
mod taskrun_fence;
mod taskrun_origins;
mod taskrun_replay;
mod workspace_mutations;

use project_mutations::*;
use queries::*;
use workspace_mutations::*;

/// Durable repository composed over the same writer as TaskRun persistence.
#[derive(Clone)]
pub struct ProjectWorkspaceStore {
    store: StoreTransaction,
}

impl ProjectWorkspaceStore {
    /// Composes the repository with the authoritative runtime store.
    pub fn from_store(store: StoreTransaction) -> Self {
        Self { store }
    }

    /// Runs a bounded operation while the authoritative Workspace version is
    /// held by the Project/Workspace writer transaction.
    pub fn with_current_workspace_version<T>(
        &self,
        principal: &str,
        id: WorkspaceId,
        operation: impl FnOnce(u64) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.store
            .with_project_workspace_transaction(|transaction| {
                let version = transaction
                    .query_row(
                        "SELECT version FROM workspaces
                     WHERE workspace_id = ?1 AND principal_id = ?2 AND live = 1",
                        params![id.as_bytes(), principal],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(|_| Error::InvariantViolation)?
                    .ok_or(Error::NotFound)?;
                let version = u64::try_from(version).map_err(|_| Error::InvariantViolation)?;
                operation(version)
            })
    }
}

impl ProjectWorkspaceRepository for ProjectWorkspaceStore {
    fn create_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        project: Project,
    ) -> Result<Project, Error> {
        create_project(&self.store, principal, command_id, key, project)
    }

    fn archive_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
    ) -> Result<Project, Error> {
        change_project(
            &self.store,
            principal,
            command_id,
            key,
            id,
            expected_version,
            receipts::Operation::ArchiveProject,
        )
    }

    fn restore_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
    ) -> Result<Project, Error> {
        change_project(
            &self.store,
            principal,
            command_id,
            key,
            id,
            expected_version,
            receipts::Operation::RestoreProject,
        )
    }

    fn delete_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
    ) -> Result<u64, Error> {
        delete_project(
            &self.store,
            principal,
            command_id,
            key,
            id,
            expected_version,
        )
    }

    fn create_workspace(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        workspace: Workspace,
    ) -> Result<Workspace, Error> {
        create_workspace(&self.store, principal, command_id, key, workspace)
    }

    fn open_workspace(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        expected_version: u64,
    ) -> Result<Workspace, Error> {
        change_workspace(
            &self.store,
            principal,
            command_id,
            key,
            id,
            expected_version,
            receipts::Operation::OpenWorkspace,
            None,
        )
    }

    fn bind_workspace_root(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        expected_version: u64,
        authorizer: &mut dyn RootAdmissionAuthorizer,
    ) -> Result<Workspace, Error> {
        change_workspace(
            &self.store,
            principal,
            command_id,
            key,
            id,
            expected_version,
            receipts::Operation::BindWorkspaceRoot,
            Some(authorizer),
        )
    }

    fn list_projects(
        &self,
        principal: &str,
        limit: runne_api::ProjectWorkspacePageSize,
        after: Option<ProjectId>,
    ) -> Result<(Vec<Project>, Option<ProjectId>), Error> {
        list_projects(&self.store, principal, limit, after)
    }

    fn get_project(&self, principal: &str, id: ProjectId) -> Result<Project, Error> {
        get_project(&self.store, principal, id)
    }

    fn list_workspaces(
        &self,
        principal: &str,
        id: ProjectId,
        limit: runne_api::ProjectWorkspacePageSize,
        after: Option<WorkspaceId>,
    ) -> Result<(Vec<Workspace>, Option<WorkspaceId>), Error> {
        list_workspaces(&self.store, principal, id, limit, after)
    }

    fn get_workspace(&self, principal: &str, id: WorkspaceId) -> Result<Workspace, Error> {
        get_workspace(&self.store, principal, id)
    }
}
