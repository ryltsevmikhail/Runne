use super::*;
use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError, RootAdmissionAuthorizer,
};
use gocode_domain::project_workspace::{Project, Workspace};
use gocode_runtime::PROJECT_WORKSPACE_WORKER_CAPACITY;
use gocode_store::ProjectWorkspaceStore;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::sync::oneshot;

#[derive(Clone)]
struct BlockingRepository {
    inner: ProjectWorkspaceStore,
    gate: Arc<BlockingGate>,
}

struct BlockingGate {
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
    fn release(&self) {
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
        limit: u16,
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
        limit: u16,
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

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn blocked_host() -> (
    tempfile::TempDir,
    gocode_runtime::RuntimeProjectWorkspaceHost<
        BlockingRepository,
        support::UnavailableAdmission,
        support::UnavailableAdmission,
    >,
    oneshot::Receiver<()>,
    Arc<BlockingGate>,
) {
    let (directory, repository) = support::test_repository();
    let (repository, entered, gate) = BlockingRepository::new(repository);
    (directory, support::host_for(repository), entered, gate)
}

#[tokio::test]
async fn saturated_worker_returns_backpressure_and_never_blocks_tokio() {
    let (_directory, host, entered, gate) = blocked_host();
    let owner = principal("owner");
    let mut blocker = Box::pin(host.create_project(
        context(owner.clone(), &command_id(80), "worker-blocker"),
        CreateProjectCommand {
            project_id: project_id(80),
            display_name: name("Blocker"),
        },
    ));
    assert!(poll_once(blocker.as_mut()).is_pending());
    entered.await.unwrap();

    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::time::sleep(Duration::from_millis(1)),
    )
    .await
    .expect("Tokio timer must run while the synchronous repository is blocked");

    let mut queued = Vec::with_capacity(PROJECT_WORKSPACE_WORKER_CAPACITY);
    for tail in 0..PROJECT_WORKSPACE_WORKER_CAPACITY {
        let mut query = Box::pin(host.get_project(
            ProjectQueryContext {
                principal: owner.clone(),
            },
            project_id(100 + tail as u8),
        ));
        assert!(poll_once(query.as_mut()).is_pending());
        queued.push(query);
    }
    let mut overflow =
        Box::pin(host.get_project(ProjectQueryContext { principal: owner }, project_id(0xfe)));
    assert_eq!(
        poll_once(overflow.as_mut()),
        Poll::Ready(Err(ProjectWorkspaceHostError::Backpressure))
    );

    gate.release();
    assert_eq!(blocker.await.unwrap().new_version, 1);
    for query in queued {
        assert_eq!(query.await.err(), Some(ProjectWorkspaceHostError::NotFound));
    }
}

#[tokio::test]
async fn shutdown_closes_pending_replies_and_future_command_and_query_calls() {
    let (_directory, host, entered, gate) = blocked_host();
    let owner = principal("owner");
    let mut blocker = Box::pin(host.create_project(
        context(owner.clone(), &command_id(81), "shutdown-blocker"),
        CreateProjectCommand {
            project_id: project_id(81),
            display_name: name("Blocker"),
        },
    ));
    assert!(poll_once(blocker.as_mut()).is_pending());
    entered.await.unwrap();

    let mut shutdown = Box::pin(host.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    let mut pending_command = Box::pin(host.create_project(
        context(owner.clone(), &command_id(82), "pending-command"),
        CreateProjectCommand {
            project_id: project_id(82),
            display_name: name("Pending"),
        },
    ));
    assert!(poll_once(pending_command.as_mut()).is_pending());
    let mut pending_query = Box::pin(host.get_project(
        ProjectQueryContext {
            principal: owner.clone(),
        },
        project_id(82),
    ));
    assert!(poll_once(pending_query.as_mut()).is_pending());

    gate.release();
    blocker.await.unwrap();
    shutdown.await;
    assert_eq!(
        pending_command.await.err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
    assert_eq!(
        pending_query.await.err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
    assert_eq!(
        host.create_project(
            context(owner.clone(), &command_id(83), "after-shutdown"),
            CreateProjectCommand {
                project_id: project_id(83),
                display_name: name("Closed")
            },
        )
        .await
        .err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
    assert_eq!(
        host.get_project(ProjectQueryContext { principal: owner }, project_id(83))
            .await
            .err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
}
