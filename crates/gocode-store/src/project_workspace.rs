//! Durable Project/Workspace repository sharing the authoritative SQLite writer.

use crate::store::StoreTransaction;
use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, Workspace};

mod fingerprint;
pub(crate) mod lineage;
mod mutation_support;
mod project_mutations;
mod queries;
mod receipts;
mod records;
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
        admission_digest: &[u8; 32],
    ) -> Result<Workspace, Error> {
        change_workspace(
            &self.store,
            principal,
            command_id,
            key,
            id,
            expected_version,
            receipts::Operation::BindWorkspaceRoot,
            Some(admission_digest),
        )
    }

    fn list_projects(&self, principal: &str) -> Result<Vec<Project>, Error> {
        list_projects(&self.store, principal)
    }

    fn get_project(&self, principal: &str, id: ProjectId) -> Result<Project, Error> {
        get_project(&self.store, principal, id)
    }

    fn list_workspaces(&self, principal: &str, id: ProjectId) -> Result<Vec<Workspace>, Error> {
        list_workspaces(&self.store, principal, id)
    }

    fn get_workspace(&self, principal: &str, id: WorkspaceId) -> Result<Workspace, Error> {
        get_workspace(&self.store, principal, id)
    }
}
