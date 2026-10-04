// Supervisor — worker lifecycle management and ingress routing.

use std::collections::HashMap;
use std::sync::Arc;

use runne_application::commands::{CommandOutcome, CreateTaskRunInput, SubmitTaskRunInput};
use runne_application::conversation_text_service::ConversationTextCommandService;
use runne_application::ports::{ApplicationCommandContext, EventStore, IdGenerator, UnitOfWork};
use runne_application::service::TaskRunService;
use runne_domain::id::TaskRunId;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService,
};
use crate::config::RuntimeConfig;
use crate::controller::{ControlCommand, ShutdownMode, ShutdownOutcome};
use crate::error::{QueueKind, RuntimeError};
use crate::gate::AdmissionGate;
use crate::types::CanonicalProviderReply;
use crate::types::{
    AdmittedPerRunRequest, AdmittedRequest, ConversationTextCall, ConversationTextReply,
    InFlightLease, PerRunRequest, Reply, RuntimeRequest,
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
    Submit {
        outcome: Result<CommandOutcome, RuntimeError>,
        reply: Reply,
    },
    ConversationText {
        outcome: Result<runne_application::ports::TextGenerationReceipt, RuntimeError>,
        reply: ConversationTextReply,
    },
    CanonicalProvider {
        outcome: Result<
            runne_application::ports::TextGenerationReceipt,
            CanonicalProviderExecutionError,
        >,
        reply: CanonicalProviderReply,
        lease: InFlightLease,
    },
    AutomaticTaskRunQueue,
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
    conversation_service: Option<Arc<dyn ConversationTextCommandService>>,
    provider_service: Option<Arc<dyn CanonicalProviderExecutionService>>,
    automatic_taskrun_stop: CancellationToken,
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
        conversation_service: Option<Arc<dyn ConversationTextCommandService>>,
        provider_service: Option<Arc<dyn CanonicalProviderExecutionService>>,
        taskrun_execution: Option<Arc<dyn AutomaticTaskRunService>>,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.worker_max_concurrent_blocking));
        let mut registry = Self {
            workers: HashMap::new(),
            join_set: JoinSet::new(),
            semaphore,
            config,
            cancel,
            service,
            conversation_service,
            provider_service,
            automatic_taskrun_stop: CancellationToken::new(),
        };
        registry.start_automatic_taskrun_worker(taskrun_execution);
        registry
    }

    fn spawn_canonical_provider_task(
        &mut self,
        job: CanonicalProviderExecutionJob,
        reply: CanonicalProviderReply,
        lease: InFlightLease,
    ) {
        let Some(service) = self.provider_service.clone() else {
            let _ = reply.send(Err(CanonicalProviderExecutionError::Unavailable));
            return;
        };
        self.join_set.spawn(async move {
            let outcome = service.execute(job).await;
            RuntimeTaskExit::CanonicalProvider {
                outcome,
                reply,
                lease,
            }
        });
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

    /// Spawns the atomic submit unit-of-work for a new aggregate. The
    /// TaskRun id is generated inside `submit_task_run`, so this task never
    /// routes through a per-run worker mailbox.
    fn spawn_submit_task(
        &mut self,
        context: ApplicationCommandContext,
        input: SubmitTaskRunInput,
        service: Arc<TaskRunService<E, U, I>>,
        reply: Reply,
    ) {
        self.join_set.spawn(async move {
            let outcome = service
                .submit_task_run(&context, input)
                .map_err(RuntimeError::Application);
            RuntimeTaskExit::Submit { outcome, reply }
        });
    }

    fn spawn_submit_legacy_task(
        &mut self,
        context: ApplicationCommandContext,
        input: runne_application::commands::LegacySubmitTaskRunInput,
        service: Arc<TaskRunService<E, U, I>>,
        reply: Reply,
    ) {
        self.join_set.spawn(async move {
            let outcome = service
                .submit_task_run_legacy(&context, input)
                .map_err(RuntimeError::Application);
            RuntimeTaskExit::Submit { outcome, reply }
        });
    }

    fn spawn_conversation_text_task(
        &mut self,
        call: ConversationTextCall,
        reply: ConversationTextReply,
    ) {
        let Some(service) = self.conversation_service.clone() else {
            let _ = reply.send(Err(RuntimeError::RuntimeClosed));
            return;
        };
        self.join_set.spawn(async move {
            let outcome = call
                .execute(service.as_ref())
                .map_err(RuntimeError::ConversationApplication);
            RuntimeTaskExit::ConversationText { outcome, reply }
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
        | PerRunRequest::Cancel { reply, .. }
        | PerRunRequest::Complete { reply, .. } => reply,
    }
}
