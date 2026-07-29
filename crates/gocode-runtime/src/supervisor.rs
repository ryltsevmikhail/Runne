//! Supervisor — worker lifecycle management and ingress routing.

use std::collections::HashMap;
use std::sync::Arc;

use gocode_application::commands::{CommandOutcome, CreateTaskRunInput};
use gocode_application::ports::{ApplicationCommandContext, EventStore, IdGenerator, UnitOfWork};
use gocode_application::service::TaskRunService;
use gocode_domain::id::TaskRunId;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::RuntimeConfig;
use crate::controller::{ControlCommand, ShutdownMode, ShutdownOutcome};
use crate::error::{QueueKind, RuntimeError};
use crate::gate::AdmissionGate;
use crate::types::{
    AdmittedPerRunRequest, AdmittedRequest, InFlightLease, PerRunRequest, Reply, RuntimeRequest,
};
use crate::worker::{self, WorkerExit, WorkerGeneration};

// ── WorkerHandle ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WorkerHandle {
    generation: WorkerGeneration,
    sender: mpsc::Sender<AdmittedPerRunRequest>,
}

// ── RuntimeTaskExit ─────────────────────────────────────────────────────────

enum RuntimeTaskExit {
    Worker(WorkerExit),
    Create {
        taskrun_id: Option<TaskRunId>,
        outcome: Result<CommandOutcome, RuntimeError>,
        reply: Reply,
    },
}

// ── WorkerRegistry ──────────────────────────────────────────────────────────

struct WorkerRegistry<E, U, I>
where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    workers: HashMap<TaskRunId, WorkerHandle>,
    join_set: JoinSet<RuntimeTaskExit>,
    semaphore: Arc<Semaphore>,
    config: RuntimeConfig,
    cancel: CancellationToken,
    service: Arc<TaskRunService<E, U, I>>,
}

impl<E, U, I> WorkerRegistry<E, U, I>
where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    fn new(
        config: RuntimeConfig,
        cancel: CancellationToken,
        service: Arc<TaskRunService<E, U, I>>,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.worker_max_concurrent_blocking));
        Self {
            workers: HashMap::new(),
            join_set: JoinSet::new(),
            semaphore,
            config,
            cancel,
            service,
        }
    }

    fn get_or_spawn(&mut self, taskrun_id: TaskRunId) -> Result<WorkerHandle, RuntimeError> {
        if let Some(handle) = self.workers.get(&taskrun_id) {
            return Ok(WorkerHandle {
                generation: handle.generation,
                sender: handle.sender.clone(),
            });
        }
        self.spawn_worker(taskrun_id)
    }

    fn spawn_worker(&mut self, taskrun_id: TaskRunId) -> Result<WorkerHandle, RuntimeError> {
        if self.workers.len() >= self.config.max_active_workers {
            return Err(RuntimeError::Backpressure {
                queue: QueueKind::TaskRun,
            });
        }
        let generation = self
            .workers
            .get(&taskrun_id)
            .map(|h| h.generation.next())
            .unwrap_or_else(WorkerGeneration::initial);

        let (tx, rx) = mpsc::channel(self.config.per_run_mailbox_capacity);
        let service = Arc::clone(&self.service);
        let semaphore = Arc::clone(&self.semaphore);
        let config = self.config.clone();
        let cancel = self.cancel.child_token();

        self.join_set.spawn(async move {
            let exit = worker::run_worker(
                taskrun_id, rx, service, semaphore, config, cancel, generation,
            )
            .await;
            RuntimeTaskExit::Worker(exit)
        });

        let handle = WorkerHandle {
            generation,
            sender: tx,
        };
        self.workers.insert(taskrun_id, handle.clone());
        Ok(handle)
    }

    fn spawn_create_task(
        &mut self,
        context: ApplicationCommandContext,
        input: CreateTaskRunInput,
        service: Arc<TaskRunService<E, U, I>>,
        reply: Reply,
    ) {
        self.join_set.spawn(async move {
            let outcome = service
                .create_task_run(&context, input)
                .map_err(RuntimeError::Application);
            let taskrun_id = outcome.as_ref().ok().and_then(|o| match o {
                CommandOutcome::TaskRunCreated { taskrun_id, .. } => Some(*taskrun_id),
                _ => None,
            });
            RuntimeTaskExit::Create {
                taskrun_id,
                outcome,
                reply,
            }
        });
    }

    fn remove_worker(&mut self, exit: &WorkerExit) {
        if let Some(handle) = self.workers.get(&exit.taskrun_id) {
            if handle.generation == exit.generation {
                self.workers.remove(&exit.taskrun_id);
            }
        }
    }

    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    fn close_all_workers(&mut self) {
        self.workers.clear();
    }
}

// ── extract_reply ───────────────────────────────────────────────────────────

fn extract_reply(request: PerRunRequest) -> Reply {
    match request {
        PerRunRequest::Queue { reply, .. }
        | PerRunRequest::Admit { reply, .. }
        | PerRunRequest::StartAttempt { reply, .. }
        | PerRunRequest::Complete { reply, .. } => reply,
    }
}

// ── reject_request ──────────────────────────────────────────────────────────

fn reject_request(request: RuntimeRequest) {
    match request {
        RuntimeRequest::Create { reply, .. }
        | RuntimeRequest::Queue { reply, .. }
        | RuntimeRequest::Admit { reply, .. }
        | RuntimeRequest::StartAttempt { reply, .. }
        | RuntimeRequest::Complete { reply, .. } => {
            let _ = reply.send(Err(RuntimeError::RuntimeClosed));
        }
    }
}

// ── route_to_worker ─────────────────────────────────────────────────────────

fn route_to_worker<E, U, I>(
    taskrun_id: TaskRunId,
    per_run: PerRunRequest,
    lease: InFlightLease,
    registry: &mut WorkerRegistry<E, U, I>,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let handle = match registry.get_or_spawn(taskrun_id) {
        Ok(h) => h,
        Err(e) => {
            let reply = extract_reply(per_run);
            let _ = reply.send(Err(e));
            return;
        }
    };

    let msg = AdmittedPerRunRequest {
        request: per_run,
        lease,
    };

    match handle.sender.try_send(msg) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(m)) => {
            let reply = extract_reply(m.request);
            let _ = reply.send(Err(RuntimeError::Backpressure {
                queue: QueueKind::TaskRun,
            }));
        }
        Err(mpsc::error::TrySendError::Closed(m)) => {
            // Stale handle — retry once with fresh spawn
            registry.remove_worker(&WorkerExit {
                taskrun_id,
                generation: handle.generation,
            });
            let handle2 = match registry.spawn_worker(taskrun_id) {
                Ok(h) => h,
                Err(e) => {
                    let reply = extract_reply(m.request);
                    let _ = reply.send(Err(e));
                    return;
                }
            };
            let msg2 = AdmittedPerRunRequest {
                request: m.request,
                lease: m.lease,
            };
            match handle2.sender.try_send(msg2) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(m2)) => {
                    let reply = extract_reply(m2.request);
                    let _ = reply.send(Err(RuntimeError::Backpressure {
                        queue: QueueKind::TaskRun,
                    }));
                }
                Err(mpsc::error::TrySendError::Closed(m2)) => {
                    let reply = extract_reply(m2.request);
                    let _ = reply.send(Err(RuntimeError::RuntimeClosed));
                }
            }
        }
    }
}

// ── dispatch_admitted ───────────────────────────────────────────────────────

fn dispatch_admitted<E, U, I>(
    admitted: AdmittedRequest,
    registry: &mut WorkerRegistry<E, U, I>,
    service: Arc<TaskRunService<E, U, I>>,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let AdmittedRequest { request, lease } = admitted;

    match request {
        RuntimeRequest::Create {
            context,
            input,
            reply,
        } => {
            registry.spawn_create_task(context, input, service, reply);
            drop(lease);
        }
        RuntimeRequest::Queue {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Queue {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::Admit {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Admit {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::StartAttempt {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::StartAttempt {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
        RuntimeRequest::Complete {
            context,
            input,
            reply,
            ..
        } => {
            let tid = input.taskrun_id;
            let per_run = PerRunRequest::Complete {
                context,
                input,
                reply,
            };
            route_to_worker(tid, per_run, lease, registry);
        }
    }
}

// ── run_supervisor ──────────────────────────────────────────────────────────

pub(crate) async fn run_supervisor<E, U, I>(
    mut ingress_rx: mpsc::Receiver<AdmittedRequest>,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    gate: Arc<AdmissionGate>,
    config: RuntimeConfig,
    cancel: CancellationToken,
    service: Arc<TaskRunService<E, U, I>>,
    drain_complete_tx: oneshot::Sender<ShutdownOutcome>,
) where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    let mut registry = WorkerRegistry::new(config, cancel.clone(), service.clone());
    let mut draining = false;
    let mut ingress_open = true;
    let mut control_open = true;
    let mut shutdown_ack: Option<oneshot::Sender<ShutdownOutcome>> = None;
    let mut rejected_commands: usize = 0;

    loop {
        tokio::select! {
            biased;

            cmd = control_rx.recv(), if control_open => {
                match cmd {
                    Some(ControlCommand::Shutdown { mode, ack }) => {
                        gate.drain().await;
                        gate.close();
                        draining = true;
                        shutdown_ack = Some(ack);
                        ingress_rx.close();
                        match mode {
                            ShutdownMode::Graceful { .. } => {
                                while let Ok(admitted) = ingress_rx.try_recv() {
                                    dispatch_admitted(
                                        admitted,
                                        &mut registry,
                                        Arc::clone(&service),
                                    );
                                }
                                registry.close_all_workers();
                            }
                            ShutdownMode::Immediate { .. } => {
                                while let Ok(admitted) = ingress_rx.try_recv() {
                                    reject_request(admitted.request);
                                    rejected_commands += 1;
                                }
                                cancel.cancel();
                            }
                        }
                        ingress_open = false;
                    }
                    None => {
                        control_open = false;
                        draining = true;
                    }
                }
            }

            msg = ingress_rx.recv(), if ingress_open => {
                match msg {
                    Some(admitted) => {
                        if draining {
                            reject_request(admitted.request);
                            rejected_commands += 1;
                            continue;
                        }
                        dispatch_admitted(admitted, &mut registry, Arc::clone(&service));
                    }
                    None => {
                        ingress_open = false;
                        draining = true;
                    }
                }
            }

            exit = registry.join_set.join_next(), if !registry.join_set.is_empty() => {
                match exit {
                    Some(Ok(RuntimeTaskExit::Worker(we))) => { registry.remove_worker(&we); }
                    Some(Ok(RuntimeTaskExit::Create { reply, outcome, .. })) => {
                        let _ = reply.send(outcome);
                    }
                    _ => {}
                }
            }

            else => break,
        }

        if draining && registry.worker_count() == 0 && registry.join_set.is_empty() {
            let outcome = ShutdownOutcome::Quiesced;
            if let Some(ack) = shutdown_ack.take() {
                let _ = ack.send(outcome.clone());
            }
            let _ = drain_complete_tx.send(outcome);
            return;
        }
    }

    let outcome = ShutdownOutcome::Incomplete {
        active_workers: registry.worker_count(),
        active_blocking_ops: 0,
        rejected_commands,
    };
    if let Some(ack) = shutdown_ack.take() {
        let _ = ack.send(outcome.clone());
    }
    let _ = drain_complete_tx.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use gocode_application::commands::{CommandOutcome, CreateTaskRunInput};
    use gocode_application::ports::{ApplicationCommandContext, PrincipalId, RuntimeAuthorityId};
    use gocode_domain::event::Actor;
    use gocode_domain::id::{ConversationId, IdempotencyKey, WorkspaceId};
    use gocode_store::store::StoreTransaction;

    type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

    #[tokio::test(flavor = "current_thread")]
    async fn graceful_shutdown_completes_ingress_accepted_before_the_fence() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("runtime.sqlite");
        let authority = RuntimeAuthorityId("graceful-ingress-test".to_owned());
        let store =
            StoreTransaction::open(database_path.to_str().unwrap(), authority.clone()).unwrap();
        let service: Arc<SqliteService> = Arc::new(TaskRunService::new(
            store.clone(),
            store.clone(),
            store,
            authority,
        ));
        let config = RuntimeConfig::default();
        let gate = Arc::new(AdmissionGate::new(config.max_in_flight_requests));
        let cancel = CancellationToken::new();
        let (ingress_tx, ingress_rx) = mpsc::channel(1);
        let (control_tx, control_rx) = mpsc::channel(1);
        let (drain_complete_tx, drain_complete_rx) = oneshot::channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        let lease = InFlightLease::new(Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap());

        ingress_tx
            .send(AdmittedRequest {
                request: RuntimeRequest::Create {
                    context: ApplicationCommandContext {
                        command_id: "018f2e3a-7000-7000-8000-000000000001".parse().unwrap(),
                        idempotency_key: IdempotencyKey::new("accepted-before-fence").unwrap(),
                        principal_id: PrincipalId("test".to_owned()),
                        actor: Actor::new("test").unwrap(),
                    },
                    input: CreateTaskRunInput {
                        conversation_id: "018f2e3a-7000-7000-8000-00000000000a"
                            .parse::<ConversationId>()
                            .unwrap(),
                        workspace_id: "018f2e3a-7000-7000-8000-00000000000b"
                            .parse::<WorkspaceId>()
                            .unwrap(),
                    },
                    reply: reply_tx,
                },
                lease,
            })
            .await
            .unwrap();

        let (shutdown_ack_tx, shutdown_ack_rx) = oneshot::channel();
        control_tx
            .send(ControlCommand::Shutdown {
                mode: ShutdownMode::Graceful {
                    timeout: Duration::from_secs(5),
                },
                ack: shutdown_ack_tx,
            })
            .await
            .unwrap();

        tokio::spawn(run_supervisor(
            ingress_rx,
            control_rx,
            gate,
            config,
            cancel,
            service,
            drain_complete_tx,
        ));

        let command_outcome = tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .expect("accepted command must complete before shutdown")
            .expect("accepted command reply sender must remain alive")
            .expect("accepted command must succeed");
        assert!(matches!(
            command_outcome,
            CommandOutcome::TaskRunCreated { .. }
        ));

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), shutdown_ack_rx)
                .await
                .expect("shutdown acknowledgement must be bounded")
                .expect("shutdown acknowledgement sender must remain alive"),
            ShutdownOutcome::Quiesced
        );
        assert_eq!(drain_complete_rx.await.unwrap(), ShutdownOutcome::Quiesced);
    }
}
