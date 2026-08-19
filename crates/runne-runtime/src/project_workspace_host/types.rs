use runne_api::{
    BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand, ExistingProjectCommand,
    ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext, ProjectPage,
    ProjectPageRequest, ProjectQueryContext, ProjectWorkspaceHostError, WorkspaceCommandAck,
    WorkspacePage, WorkspacePageRequest,
};
use runne_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionVerifier,
};
use runne_application::project_workspace_service::{
    ProjectWorkspaceService, ProjectWorkspaceServiceError,
};
use runne_domain::id::{ProjectId, WorkspaceId};
use std::marker::PhantomData;
use tokio::sync::{mpsc, oneshot};

/// Fixed admission bound for the dedicated Project/Workspace runtime worker.
pub const PROJECT_WORKSPACE_WORKER_CAPACITY: usize = 32;
type HostMarker<R, C, V> = PhantomData<fn() -> (R, C, V)>;

/// Runtime composition root for principal-bound Project and Workspace ports.
pub struct RuntimeProjectWorkspaceHost<R, C, V> {
    sender: mpsc::Sender<WorkItem>,
    marker: HostMarker<R, C, V>,
}

impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    RuntimeProjectWorkspaceHost<R, C, V>
{
    /// Creates a host with one dedicated blocking worker over the authoritative store.
    pub fn new(repository: R, current_admission: C, admission_verifier: V) -> Self {
        let (sender, receiver) = mpsc::channel(PROJECT_WORKSPACE_WORKER_CAPACITY);
        let service =
            ProjectWorkspaceService::new(repository, current_admission, admission_verifier);
        let _ = std::thread::Builder::new()
            .name("runne-project-workspace".into())
            .spawn(move || run_worker(service, receiver));
        Self {
            sender,
            marker: PhantomData,
        }
    }

    pub(super) async fn submit<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, ProjectWorkspaceHostError>>) -> WorkItem,
    ) -> Result<T, ProjectWorkspaceHostError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(build(reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ProjectWorkspaceHostError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ProjectWorkspaceHostError::Unavailable,
            })?;
        response
            .await
            .map_err(|_| ProjectWorkspaceHostError::Unavailable)?
    }

    /// Stops the dedicated worker; subsequent calls fail closed as unavailable.
    pub async fn shutdown(&self) {
        let (reply, response) = oneshot::channel();
        if self.sender.send(WorkItem::Shutdown(reply)).await.is_ok() {
            let _ = response.await;
        }
    }
}

pub(super) enum WorkItem {
    Shutdown(oneshot::Sender<()>),
    CreateProject(
        ProjectCommandContext,
        CreateProjectCommand,
        Reply<ProjectCommandAck>,
    ),
    ArchiveProject(
        ProjectCommandContext,
        ExistingProjectCommand,
        Reply<ProjectCommandAck>,
    ),
    RestoreProject(
        ProjectCommandContext,
        ExistingProjectCommand,
        Reply<ProjectCommandAck>,
    ),
    DeleteProject(
        ProjectCommandContext,
        ExistingProjectCommand,
        Reply<ProjectCommandAck>,
    ),
    CreateWorkspace(
        ProjectCommandContext,
        CreateWorkspaceCommand,
        Reply<WorkspaceCommandAck>,
    ),
    OpenWorkspace(
        ProjectCommandContext,
        ExistingWorkspaceCommand,
        Reply<WorkspaceCommandAck>,
    ),
    BindWorkspaceRoot(
        ProjectCommandContext,
        BindWorkspaceRootCommand,
        Reply<WorkspaceCommandAck>,
    ),
    ListProjects(ProjectQueryContext, ProjectPageRequest, Reply<ProjectPage>),
    GetProject(
        ProjectQueryContext,
        ProjectId,
        Reply<runne_api::ProjectSnapshot>,
    ),
    ListWorkspaces(
        ProjectQueryContext,
        ProjectId,
        WorkspacePageRequest,
        Reply<WorkspacePage>,
    ),
    GetWorkspace(
        ProjectQueryContext,
        WorkspaceId,
        Reply<runne_api::WorkspaceSnapshot>,
    ),
}

type Reply<T> = oneshot::Sender<Result<T, ProjectWorkspaceHostError>>;

fn run_worker<
    R: ProjectWorkspaceRepository,
    C: CurrentRootAdmissionContext,
    V: RootAdmissionVerifier,
>(
    service: ProjectWorkspaceService<R, C, V>,
    mut receiver: mpsc::Receiver<WorkItem>,
) {
    while let Some(item) = receiver.blocking_recv() {
        match item {
            WorkItem::Shutdown(reply) => {
                drop(receiver);
                drop(service);
                let _ = reply.send(());
                return;
            }
            WorkItem::CreateProject(context, command, reply) => {
                reply_result(reply, service.create_project(context, command))
            }
            WorkItem::ArchiveProject(context, command, reply) => {
                reply_result(reply, service.archive_project(context, command))
            }
            WorkItem::RestoreProject(context, command, reply) => {
                reply_result(reply, service.restore_project(context, command))
            }
            WorkItem::DeleteProject(context, command, reply) => {
                reply_result(reply, service.delete_project(context, command))
            }
            WorkItem::CreateWorkspace(context, command, reply) => {
                reply_result(reply, service.create_workspace(context, command))
            }
            WorkItem::OpenWorkspace(context, command, reply) => {
                reply_result(reply, service.open_workspace(context, command))
            }
            WorkItem::BindWorkspaceRoot(context, command, reply) => {
                reply_result(reply, service.bind_workspace_root(context, command))
            }
            WorkItem::ListProjects(context, request, reply) => {
                reply_result(reply, service.list_projects(context, request))
            }
            WorkItem::GetProject(context, id, reply) => {
                reply_result(reply, service.get_project(context, id))
            }
            WorkItem::ListWorkspaces(context, id, request, reply) => {
                reply_result(reply, service.list_workspaces(context, id, request))
            }
            WorkItem::GetWorkspace(context, id, reply) => {
                reply_result(reply, service.get_workspace(context, id))
            }
        }
    }
}

fn reply_result<T>(reply: Reply<T>, result: Result<T, ProjectWorkspaceServiceError>) {
    let _ = reply.send(result.map_err(map_service_error));
}

fn map_service_error(error: ProjectWorkspaceServiceError) -> ProjectWorkspaceHostError {
    match error {
        ProjectWorkspaceServiceError::NotFound => ProjectWorkspaceHostError::NotFound,
        ProjectWorkspaceServiceError::Conflict => ProjectWorkspaceHostError::Conflict,
        ProjectWorkspaceServiceError::Forbidden => ProjectWorkspaceHostError::Forbidden,
        ProjectWorkspaceServiceError::Unavailable => ProjectWorkspaceHostError::Unavailable,
        ProjectWorkspaceServiceError::InvariantViolation => {
            ProjectWorkspaceHostError::InvariantViolation
        }
    }
}
