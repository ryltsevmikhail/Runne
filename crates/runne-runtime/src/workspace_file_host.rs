//! Runtime host for authenticated Workspace file projections.

use runne_api::{
    WorkspaceFileContent, WorkspaceFileHostError, WorkspaceFileHostPort, WorkspaceFileListRequest,
    WorkspaceFilePage, WorkspaceFileQueryContext, WorkspaceFileReadRequest,
};
use runne_application::ports::WorkspaceFileProvider;
use std::marker::PhantomData;
use tokio::sync::{mpsc, oneshot};

const WORKER_CAPACITY: usize = 32;

pub struct RuntimeWorkspaceFileHost<P> {
    sender: mpsc::Sender<WorkItem>,
    marker: PhantomData<fn() -> P>,
}

impl<P: WorkspaceFileProvider> RuntimeWorkspaceFileHost<P> {
    #[must_use]
    pub fn new(provider: P) -> Self {
        let (sender, receiver) = mpsc::channel(WORKER_CAPACITY);
        let _ = std::thread::Builder::new()
            .name("runne-workspace-files".into())
            .spawn(move || run_worker(provider, receiver));
        Self {
            sender,
            marker: PhantomData,
        }
    }

    async fn submit<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, WorkspaceFileHostError>>) -> WorkItem,
    ) -> Result<T, WorkspaceFileHostError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(build(reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => WorkspaceFileHostError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => WorkspaceFileHostError::Unavailable,
            })?;
        response
            .await
            .map_err(|_| WorkspaceFileHostError::Unavailable)?
    }

    pub async fn shutdown(&self) {
        let (reply, response) = oneshot::channel();
        if self.sender.send(WorkItem::Shutdown(reply)).await.is_ok() {
            let _ = response.await;
        }
    }
}

impl<P: WorkspaceFileProvider> WorkspaceFileHostPort for RuntimeWorkspaceFileHost<P> {
    async fn list_files(
        &self,
        context: WorkspaceFileQueryContext,
        request: WorkspaceFileListRequest,
    ) -> Result<WorkspaceFilePage, WorkspaceFileHostError> {
        self.submit(|reply| WorkItem::List(context, request, reply))
            .await
    }

    async fn read_file(
        &self,
        context: WorkspaceFileQueryContext,
        request: WorkspaceFileReadRequest,
    ) -> Result<WorkspaceFileContent, WorkspaceFileHostError> {
        self.submit(|reply| WorkItem::Read(context, request, reply))
            .await
    }
}

enum WorkItem {
    Shutdown(oneshot::Sender<()>),
    List(
        WorkspaceFileQueryContext,
        WorkspaceFileListRequest,
        oneshot::Sender<Result<WorkspaceFilePage, WorkspaceFileHostError>>,
    ),
    Read(
        WorkspaceFileQueryContext,
        WorkspaceFileReadRequest,
        oneshot::Sender<Result<WorkspaceFileContent, WorkspaceFileHostError>>,
    ),
}

fn run_worker<P: WorkspaceFileProvider>(provider: P, mut receiver: mpsc::Receiver<WorkItem>) {
    while let Some(item) = receiver.blocking_recv() {
        match item {
            WorkItem::Shutdown(reply) => {
                let _ = reply.send(());
                return;
            }
            WorkItem::List(context, request, reply) => {
                let _ = reply.send(provider.list_files(context.principal.as_str(), &request));
            }
            WorkItem::Read(context, request, reply) => {
                let _ = reply.send(provider.read_file(context.principal.as_str(), &request));
            }
        }
    }
}
