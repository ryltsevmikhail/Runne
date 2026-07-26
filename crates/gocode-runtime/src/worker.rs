//! Per-taskrun worker loop — sequential processing of commands.

use std::sync::Arc;

use gocode_application::ports::{EventStore, IdGenerator, UnitOfWork};
use gocode_application::service::TaskRunService;
use gocode_domain::id::TaskRunId;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::config::RuntimeConfig;
use crate::error::{QueueKind, RuntimeError, WorkerFailureKind};
use crate::types::{AdmittedPerRunRequest, InFlightLease, PerRunCall, Reply};

/// Monotonically increasing generation counter for a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct WorkerGeneration(pub(crate) u64);

impl WorkerGeneration {
    pub(crate) fn initial() -> Self {
        Self(1)
    }
    pub(crate) fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// Emitted by a worker when it terminates.
#[derive(Debug, Clone)]
pub(crate) struct WorkerExit {
    pub(crate) taskrun_id: TaskRunId,
    pub(crate) generation: WorkerGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerExitDisposition {
    Idle,
    Graceful,
    Immediate,
}

pub(crate) async fn run_worker<E, U, I>(
    taskrun_id: TaskRunId,
    mut rx: mpsc::Receiver<AdmittedPerRunRequest>,
    service: Arc<TaskRunService<E, U, I>>,
    semaphore: Arc<Semaphore>,
    config: RuntimeConfig,
    cancel: CancellationToken,
    generation: WorkerGeneration,
) -> WorkerExit
where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let disposition = loop {
        let req = tokio::select! {
            biased;
            _ = cancel.cancelled() => break WorkerExitDisposition::Immediate,
            _ = tokio::time::sleep(config.worker_idle_timeout) => break WorkerExitDisposition::Idle,
            req = rx.recv() => match req {
                Some(r) => r,
                None => break WorkerExitDisposition::Graceful,
            },
        };
        let (call, reply) = req.request.into_parts();
        let lease = req.lease;
        execute_request(
            call, reply, lease, taskrun_id, &service, &semaphore, &config, &cancel,
        )
        .await;
    };
    drain_mailbox(
        &mut rx,
        disposition,
        taskrun_id,
        &service,
        &semaphore,
        &config,
        &cancel,
    )
    .await;
    WorkerExit {
        taskrun_id,
        generation,
    }
}

async fn execute_request<E, U, I>(
    call: PerRunCall,
    reply: Reply,
    _lease: InFlightLease,
    taskrun_id: TaskRunId,
    service: &Arc<TaskRunService<E, U, I>>,
    semaphore: &Arc<Semaphore>,
    config: &RuntimeConfig,
    cancel: &CancellationToken,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let permit = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            let _ = reply.send(Err(RuntimeError::RuntimeClosed));
            return;
        }
        p = tokio::time::timeout(config.blocking_acquire_timeout, semaphore.clone().acquire_owned()) => {
            match p {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => { let _ = reply.send(Err(RuntimeError::RuntimeClosed)); return; }
                Err(_) => {
                    let _ = reply.send(Err(RuntimeError::Backpressure { queue: QueueKind::BlockingPool }));
                    return;
                }
            }
        }
    };
    let svc = Arc::clone(service);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        call.execute(svc.as_ref())
    })
    .await;
    let outcome = match result {
        Ok(Ok(o)) => Ok(o),
        Ok(Err(e)) => Err(RuntimeError::Application(e)),
        Err(join_err) => Err(RuntimeError::WorkerExecutionFailed {
            taskrun_id: Some(taskrun_id),
            kind: if join_err.is_panic() {
                WorkerFailureKind::WorkerPanicked
            } else {
                WorkerFailureKind::BlockingPoolClosed
            },
        }),
    };
    let _ = reply.send(outcome);
}

async fn drain_mailbox<E, U, I>(
    rx: &mut mpsc::Receiver<AdmittedPerRunRequest>,
    disposition: WorkerExitDisposition,
    taskrun_id: TaskRunId,
    service: &Arc<TaskRunService<E, U, I>>,
    semaphore: &Arc<Semaphore>,
    config: &RuntimeConfig,
    cancel: &CancellationToken,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    if disposition == WorkerExitDisposition::Immediate {
        rx.close();
        while let Ok(req) = rx.try_recv() {
            let (_, reply) = req.request.into_parts();
            let _ = reply.send(Err(RuntimeError::RuntimeClosed));
        }
    } else {
        rx.close();
        while let Some(req) = rx.recv().await {
            let (call, reply) = req.request.into_parts();
            let lease = req.lease;
            execute_request(
                call, reply, lease, taskrun_id, service, semaphore, config, cancel,
            )
            .await;
        }
    }
}
