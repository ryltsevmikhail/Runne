//! Durable Project/Workspace repository sharing the authoritative SQLite writer.

use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, Workspace};
use std::sync::Arc;

use crate::store::StoreTransaction;

mod fingerprint;
mod mutation_support;
mod project_mutations;
mod queries;
mod receipts;
mod records;
mod taskrun_fence;
mod workspace_mutations;

pub(crate) use taskrun_fence::validate_taskrun_workspace_scope;

use project_mutations::*;
use queries::*;
use workspace_mutations::*;

/// Durable repository composed over the same writer as TaskRun persistence.
#[derive(Clone)]
pub struct ProjectWorkspaceStore {
    store: StoreTransaction,
    _cleanup: Option<Arc<EphemeralDatabase>>,
}

impl ProjectWorkspaceStore {
    /// Composes the repository with the authoritative runtime store.
    pub fn from_store(store: StoreTransaction) -> Self {
        Self {
            store,
            _cleanup: None,
        }
    }

    /// Compatibility constructor for isolated host tests.
    pub fn new() -> Self {
        let path = ephemeral_path();
        let store = StoreTransaction::open(
            path.to_str()
                .expect("temporary database path must be UTF-8"),
            RuntimeAuthorityId("project-workspace-isolated".into()),
            Arc::new(IsolatedGuard),
        )
        .expect("isolated Project/Workspace database must open");
        Self {
            store,
            _cleanup: Some(Arc::new(EphemeralDatabase(path))),
        }
    }
}

impl Default for ProjectWorkspaceStore {
    fn default() -> Self {
        Self::new()
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

struct IsolatedGuard;

impl ProhibitedContentPort for IsolatedGuard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 0 })
    }
}

struct EphemeralDatabase(std::path::PathBuf);

impl Drop for EphemeralDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

fn ephemeral_path() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    std::env::temp_dir().join(format!(
        "gocode-project-workspace-{}-{}.sqlite",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
