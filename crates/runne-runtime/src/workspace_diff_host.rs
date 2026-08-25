//! Runtime host for authenticated Workspace change and diff projections.

use runne_api::{
    WorkspaceChangeListRequest, WorkspaceChangeSet, WorkspaceDiff, WorkspaceDiffHostError,
    WorkspaceDiffHostPort, WorkspaceDiffQueryContext, WorkspaceDiffReadRequest,
};
use runne_application::ports::WorkspaceDiffProvider;
use std::marker::PhantomData;
use tokio::sync::{mpsc, oneshot};

const WORKER_CAPACITY: usize = 32;

pub struct RuntimeWorkspaceDiffHost<P> {
    sender: mpsc::Sender<WorkItem>,
    marker: PhantomData<fn() -> P>,
}

impl<P: WorkspaceDiffProvider> RuntimeWorkspaceDiffHost<P> {
    #[must_use]
    pub fn new(provider: P) -> Self {
        let (sender, receiver) = mpsc::channel(WORKER_CAPACITY);
        let _ = std::thread::Builder::new()
            .name("runne-workspace-diff".into())
            .spawn(move || run_worker(provider, receiver));
        Self {
            sender,
            marker: PhantomData,
        }
    }

    async fn submit<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, WorkspaceDiffHostError>>) -> WorkItem,
    ) -> Result<T, WorkspaceDiffHostError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(build(reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => WorkspaceDiffHostError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => WorkspaceDiffHostError::Unavailable,
            })?;
        response
            .await
            .map_err(|_| WorkspaceDiffHostError::Unavailable)?
    }

    pub async fn shutdown(&self) {
        let (reply, response) = oneshot::channel();
        if self.sender.send(WorkItem::Shutdown(reply)).await.is_ok() {
            let _ = response.await;
        }
    }
}

impl<P: WorkspaceDiffProvider> WorkspaceDiffHostPort for RuntimeWorkspaceDiffHost<P> {
    async fn list_changes(
        &self,
        context: WorkspaceDiffQueryContext,
        request: WorkspaceChangeListRequest,
    ) -> Result<WorkspaceChangeSet, WorkspaceDiffHostError> {
        self.submit(|reply| WorkItem::List(context, request, reply))
            .await
    }

    async fn read_diff(
        &self,
        context: WorkspaceDiffQueryContext,
        request: WorkspaceDiffReadRequest,
    ) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
        self.submit(|reply| WorkItem::Read(context, request, reply))
            .await
    }
}

enum WorkItem {
    Shutdown(oneshot::Sender<()>),
    List(
        WorkspaceDiffQueryContext,
        WorkspaceChangeListRequest,
        oneshot::Sender<Result<WorkspaceChangeSet, WorkspaceDiffHostError>>,
    ),
    Read(
        WorkspaceDiffQueryContext,
        WorkspaceDiffReadRequest,
        oneshot::Sender<Result<WorkspaceDiff, WorkspaceDiffHostError>>,
    ),
}

fn run_worker<P: WorkspaceDiffProvider>(provider: P, mut receiver: mpsc::Receiver<WorkItem>) {
    while let Some(item) = receiver.blocking_recv() {
        match item {
            WorkItem::Shutdown(reply) => {
                let _ = reply.send(());
                return;
            }
            WorkItem::List(context, request, reply) => {
                let result = provider
                    .list_changes(context.principal.as_str(), &request)
                    .and_then(|set| {
                        (set.entries().len() <= usize::from(request.limit()))
                            .then_some(set)
                            .ok_or(WorkspaceDiffHostError::InvariantViolation)
                    });
                let _ = reply.send(result);
            }
            WorkItem::Read(context, request, reply) => {
                let result = provider
                    .read_diff(context.principal.as_str(), &request)
                    .and_then(|diff| {
                        (diff.path() == request.relative_path())
                            .then_some(diff)
                            .ok_or(WorkspaceDiffHostError::InvariantViolation)
                    });
                let _ = reply.send(result);
            }
        }
    }
}
