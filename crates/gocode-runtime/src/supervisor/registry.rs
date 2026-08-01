use std::collections::HashMap;
use std::sync::Arc;

use gocode_application::commands::{CommandOutcome, CreateTaskRunInput};
use gocode_application::conversation_text_service::ConversationTextCommandService;
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
    ConversationText {
        outcome: Result<gocode_application::ports::TextGenerationReceipt, RuntimeError>,
        reply: ConversationTextReply,
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
    conversation_service: Option<Arc<dyn ConversationTextCommandService>>,
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
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.worker_max_concurrent_blocking));
        Self {
            workers: HashMap::new(),
            join_set: JoinSet::new(),
            semaphore,
            config,
            cancel,
            service,
            conversation_service,
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
