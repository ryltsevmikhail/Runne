//! Runtime worker for the scoped native editor action.

use runne_api::{
    EditorLaunchReceipt, OpenEditorRequest, ProcessCommandContext, WorkspaceEditorHostError,
    WorkspaceEditorHostPort,
};
use runne_application::ports::WorkspaceEditorProvider;
use tokio::sync::{mpsc, oneshot};

const WORKER_CAPACITY: usize = 16;

/// Bounded runtime queue around the native editor provider.
pub struct RuntimeWorkspaceEditorHost<P> {
    sender: mpsc::Sender<WorkItem>,
    marker: std::marker::PhantomData<fn() -> P>,
}

impl<P: WorkspaceEditorProvider> RuntimeWorkspaceEditorHost<P> {
    /// Starts the editor provider worker.
    #[must_use]
    pub fn new(provider: P) -> Self {
        let (sender, receiver) = mpsc::channel(WORKER_CAPACITY);
        let _ = std::thread::Builder::new()
            .name("runne-workspace-editor".into())
            .spawn(move || run_worker(provider, receiver));
        Self {
            sender,
            marker: std::marker::PhantomData,
        }
    }

    async fn submit(
        &self,
        context: ProcessCommandContext,
        request: OpenEditorRequest,
    ) -> Result<EditorLaunchReceipt, WorkspaceEditorHostError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(WorkItem::Open(context, request, reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => WorkspaceEditorHostError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => WorkspaceEditorHostError::Unavailable,
            })?;
        response
            .await
            .map_err(|_| WorkspaceEditorHostError::Unavailable)?
    }
}

impl<P: WorkspaceEditorProvider> WorkspaceEditorHostPort for RuntimeWorkspaceEditorHost<P> {
    async fn open_editor(
        &self,
        context: ProcessCommandContext,
        request: OpenEditorRequest,
    ) -> Result<EditorLaunchReceipt, WorkspaceEditorHostError> {
        self.submit(context, request).await
    }
}

enum WorkItem {
    Open(
        ProcessCommandContext,
        OpenEditorRequest,
        oneshot::Sender<Result<EditorLaunchReceipt, WorkspaceEditorHostError>>,
    ),
}

fn run_worker<P: WorkspaceEditorProvider>(provider: P, mut receiver: mpsc::Receiver<WorkItem>) {
    while let Some(WorkItem::Open(context, request, reply)) = receiver.blocking_recv() {
        let result = provider.open_editor(context.principal.as_str(), &request);
        let _ = reply.send(result);
    }
}
