use super::*;
use runne_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError, RootAdmissionAuthorizer,
};
use runne_domain::project_workspace::{Project, Workspace};
use runne_store::ProjectWorkspaceStore;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::sync::oneshot;

#[derive(Clone)]
pub(super) struct BlockingRepository {
    inner: ProjectWorkspaceStore,
    gate: Arc<BlockingGate>,
}

pub(super) struct BlockingGate {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    released: Mutex<bool>,
    release: Condvar,
}

impl BlockingRepository {
    fn new(inner: ProjectWorkspaceStore) -> (Self, oneshot::Receiver<()>, Arc<BlockingGate>) {
        let (entered, observed) = oneshot::channel();
        let gate = Arc::new(BlockingGate {
            entered: Mutex::new(Some(entered)),
            released: Mutex::new(false),
            release: Condvar::new(),
        });
        (
            Self {
                inner,
                gate: gate.clone(),
            },
            observed,
            gate,
        )
    }

    fn block_once(&self) {
        let entered = self.gate.entered.lock().unwrap().take();
        if let Some(entered) = entered {
            let _ = entered.send(());
            let mut released = self.gate.released.lock().unwrap();
            while !*released {
                released = self.gate.release.wait(released).unwrap();
            }
        }
    }
}

impl BlockingGate {
    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}

impl ProjectWorkspaceRepository for BlockingRepository {
    fn create_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        project: Project,
    ) -> Result<Project, ProjectWorkspaceRepositoryError> {
        self.block_once();
        self.inner
            .create_project(principal, command_id, key, project)
    }
    fn archive_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        version: u64,
    ) -> Result<Project, ProjectWorkspaceRepositoryError> {
        self.inner
            .archive_project(principal, command_id, key, id, version)
    }
    fn restore_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        version: u64,
    ) -> Result<Project, ProjectWorkspaceRepositoryError> {
        self.inner
            .restore_project(principal, command_id, key, id, version)
    }
    fn delete_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        version: u64,
    ) -> Result<u64, ProjectWorkspaceRepositoryError> {
        self.inner
            .delete_project(principal, command_id, key, id, version)
    }
    fn create_workspace(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        workspace: Workspace,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError> {
        self.inner
            .create_workspace(principal, command_id, key, workspace)
    }
    fn open_workspace(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        version: u64,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError> {
        self.inner
            .open_workspace(principal, command_id, key, id, version)
    }
    fn bind_workspace_root(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        version: u64,
        authorizer: &mut dyn RootAdmissionAuthorizer,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError> {
        self.inner
            .bind_workspace_root(principal, command_id, key, id, version, authorizer)
    }
    fn list_projects(
        &self,
        principal: &str,
        limit: runne_api::ProjectWorkspacePageSize,
        after: Option<ProjectId>,
    ) -> Result<(Vec<Project>, Option<ProjectId>), ProjectWorkspaceRepositoryError> {
        self.inner.list_projects(principal, limit, after)
    }
    fn get_project(
        &self,
        principal: &str,
        id: ProjectId,
    ) -> Result<Project, ProjectWorkspaceRepositoryError> {
        self.inner.get_project(principal, id)
    }
    fn list_workspaces(
        &self,
        principal: &str,
        project: ProjectId,
        limit: runne_api::ProjectWorkspacePageSize,
        after: Option<WorkspaceId>,
    ) -> Result<(Vec<Workspace>, Option<WorkspaceId>), ProjectWorkspaceRepositoryError> {
        self.inner.list_workspaces(principal, project, limit, after)
    }
    fn get_workspace(
        &self,
        principal: &str,
        id: WorkspaceId,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError> {
        self.inner.get_workspace(principal, id)
    }
}

pub(super) fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

pub(super) fn blocked_host() -> (
    tempfile::TempDir,
    runne_runtime::RuntimeProjectWorkspaceHost<
        BlockingRepository,
        super::support::UnavailableAdmission,
        super::support::UnavailableAdmission,
    >,
    oneshot::Receiver<()>,
    Arc<BlockingGate>,
) {
    let (directory, repository) = super::support::test_repository();
    let (repository, entered, gate) = BlockingRepository::new(repository);
    (
        directory,
        super::support::host_for(repository),
        entered,
        gate,
    )
}
