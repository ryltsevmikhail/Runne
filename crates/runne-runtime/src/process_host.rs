//! Runtime host for authenticated process lifecycle and bounded output.

use runne_api::{
    ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessHostPort,
    ProcessOutputPage, ProcessQueryContext, ProcessSnapshot, StartProcessCommand,
};
use runne_application::ports::ProcessProvider;
use runne_domain::id::ProcessId;
use std::marker::PhantomData;
use tokio::sync::{mpsc, oneshot};

const WORKER_CAPACITY: usize = 32;

/// Bounded runtime queue around a process provider.
pub struct RuntimeProcessHost<P> {
    sender: mpsc::Sender<WorkItem>,
    marker: PhantomData<fn() -> P>,
}

impl<P: ProcessProvider> RuntimeProcessHost<P> {
    /// Starts the provider worker with a bounded queue.
    #[must_use]
    pub fn new(provider: P) -> Self {
        let (sender, receiver) = mpsc::channel(WORKER_CAPACITY);
        let _ = std::thread::Builder::new()
            .name("runne-process-host".into())
            .spawn(move || run_worker(provider, receiver));
        Self {
            sender,
            marker: PhantomData,
        }
    }

    async fn submit<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, ProcessHostError>>) -> WorkItem,
    ) -> Result<T, ProcessHostError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(build(reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ProcessHostError::Backpressure,
                mpsc::error::TrySendError::Closed(_) => ProcessHostError::Unavailable,
            })?;
        response.await.map_err(|_| ProcessHostError::Unavailable)?
    }

    /// Shuts down the provider worker.
    pub async fn shutdown(&self) {
        let (reply, response) = oneshot::channel();
        if self.sender.send(WorkItem::Shutdown(reply)).await.is_ok() {
            let _ = response.await;
        }
    }
}

impl<P: ProcessProvider> ProcessHostPort for RuntimeProcessHost<P> {
    async fn start_process(
        &self,
        context: ProcessCommandContext,
        command: StartProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        self.submit(|reply| WorkItem::Start(context, command, reply))
            .await
    }

    async fn get_process(
        &self,
        context: ProcessQueryContext,
        process_id: ProcessId,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        self.submit(|reply| WorkItem::Get(context, process_id, reply))
            .await
    }

    async fn read_process_output(
        &self,
        context: ProcessQueryContext,
        process_id: ProcessId,
        after_sequence: u64,
        limit: u16,
    ) -> Result<ProcessOutputPage, ProcessHostError> {
        self.submit(|reply| WorkItem::Read(context, process_id, after_sequence, limit, reply))
            .await
    }

    async fn stop_process(
        &self,
        context: ProcessCommandContext,
        command: ExistingProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        self.submit(|reply| WorkItem::Stop(context, command, reply))
            .await
    }
}

enum WorkItem {
    Shutdown(oneshot::Sender<()>),
    Start(
        ProcessCommandContext,
        StartProcessCommand,
        oneshot::Sender<Result<ProcessSnapshot, ProcessHostError>>,
    ),
    Get(
        ProcessQueryContext,
        ProcessId,
        oneshot::Sender<Result<ProcessSnapshot, ProcessHostError>>,
    ),
    Read(
        ProcessQueryContext,
        ProcessId,
        u64,
        u16,
        oneshot::Sender<Result<ProcessOutputPage, ProcessHostError>>,
    ),
    Stop(
        ProcessCommandContext,
        ExistingProcessCommand,
        oneshot::Sender<Result<ProcessSnapshot, ProcessHostError>>,
    ),
}

fn run_worker<P: ProcessProvider>(provider: P, mut receiver: mpsc::Receiver<WorkItem>) {
    while let Some(item) = receiver.blocking_recv() {
        match item {
            WorkItem::Shutdown(reply) => {
                let _ = reply.send(());
                return;
            }
            WorkItem::Start(context, command, reply) => {
                let _ = reply.send(provider.start_process(&context, &command));
            }
            WorkItem::Get(context, process_id, reply) => {
                let _ = reply.send(provider.get_process(&context, process_id));
            }
            WorkItem::Read(context, process_id, after, limit, reply) => {
                let _ =
                    reply.send(provider.read_process_output(&context, process_id, after, limit));
            }
            WorkItem::Stop(context, command, reply) => {
                let _ = reply.send(provider.stop_process(&context, &command));
            }
        }
    }
}
