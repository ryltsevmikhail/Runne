//! Bounded read-only host for authoritative command reconciliation.

use runne_api::{
    CommandReconciliationContext, CommandReconciliationDisposition, CommandReconciliationHostError,
    CommandReconciliationHostPort, CommandReconciliationWitness,
};
use runne_application::command_reconciliation::{
    CommandReconciliationRepository, CommandReconciliationRepositoryError,
    CommandReconciliationService,
};
use tokio::sync::{mpsc, oneshot};

/// Default queue bound for reconciliation observations.
pub const COMMAND_RECONCILIATION_WORKER_CAPACITY: usize = 32;

/// Runtime host that serializes read-only reconciliation with the store writer.
pub struct RuntimeCommandReconciliationHost<R> {
    sender: mpsc::Sender<WorkItem>,
    marker: std::marker::PhantomData<fn() -> R>,
}

impl<R: CommandReconciliationRepository> RuntimeCommandReconciliationHost<R> {
    /// Creates a host with the standard bounded worker queue.
    pub fn new(repository: R) -> Self {
        Self::with_capacity(repository, COMMAND_RECONCILIATION_WORKER_CAPACITY)
    }

    /// Creates a host with an explicit nonzero bounded worker queue.
    pub fn with_capacity(repository: R, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let service = CommandReconciliationService::new(repository);
        let _ = std::thread::Builder::new()
            .name("runne-command-reconciliation".into())
            .spawn(move || run_worker(service, receiver));
        Self {
            sender,
            marker: std::marker::PhantomData,
        }
    }

    async fn submit(
        &self,
        context: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(WorkItem::Reconcile(context, Box::new(witness), reply))
            .map_err(map_send_error)?;
        response
            .await
            .map_err(|_| CommandReconciliationHostError::Unavailable)?
    }

    /// Stops the worker; every later request fails closed as unavailable.
    pub async fn shutdown(&self) {
        let (reply, response) = oneshot::channel();
        if self.sender.send(WorkItem::Shutdown(reply)).await.is_ok() {
            let _ = response.await;
        }
    }
}

impl<R: CommandReconciliationRepository> CommandReconciliationHostPort
    for RuntimeCommandReconciliationHost<R>
{
    async fn reconcile_command(
        &self,
        context: CommandReconciliationContext,
        witness: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        self.submit(context, witness).await
    }
}

enum WorkItem {
    Reconcile(
        CommandReconciliationContext,
        Box<CommandReconciliationWitness>,
        oneshot::Sender<Result<CommandReconciliationDisposition, CommandReconciliationHostError>>,
    ),
    Shutdown(oneshot::Sender<()>),
}

fn run_worker<R: CommandReconciliationRepository>(
    service: CommandReconciliationService<R>,
    mut receiver: mpsc::Receiver<WorkItem>,
) {
    while let Some(item) = receiver.blocking_recv() {
        match item {
            WorkItem::Reconcile(context, witness, reply) => {
                let _ = reply.send(
                    service
                        .reconcile_command(&context, &witness)
                        .map_err(map_repository_error),
                );
            }
            WorkItem::Shutdown(reply) => {
                drop(receiver);
                let _ = reply.send(());
                return;
            }
        }
    }
}

fn map_send_error(error: mpsc::error::TrySendError<WorkItem>) -> CommandReconciliationHostError {
    match error {
        mpsc::error::TrySendError::Full(_) => CommandReconciliationHostError::Backpressure,
        mpsc::error::TrySendError::Closed(_) => CommandReconciliationHostError::Unavailable,
    }
}

fn map_repository_error(
    error: CommandReconciliationRepositoryError,
) -> CommandReconciliationHostError {
    match error {
        CommandReconciliationRepositoryError::Conflict => CommandReconciliationHostError::Conflict,
        CommandReconciliationRepositoryError::Unavailable => {
            CommandReconciliationHostError::Unavailable
        }
        CommandReconciliationRepositoryError::InvariantViolation => {
            CommandReconciliationHostError::InvariantViolation
        }
    }
}
