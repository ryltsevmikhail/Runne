//! Request/response envelope types for the runtime dispatch layer.

use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::errors::ApplicationError;
use gocode_application::ports::{ApplicationCommandContext, EventStore, IdGenerator, UnitOfWork};
use gocode_application::service::TaskRunService;
use tokio::sync::{OwnedSemaphorePermit, oneshot};

use crate::error::RuntimeError;

// ── Reply ───────────────────────────────────────────────────────────────────

/// A one-shot reply channel for sending command results back to the caller.
pub(crate) type Reply = oneshot::Sender<Result<CommandOutcome, RuntimeError>>;

// ── InFlightLease ───────────────────────────────────────────────────────────

/// Owns one global in-flight permit. Released on drop — after reply is sent.
///
/// The lease travels: ingress → Create task/per-run mailbox → reply → drop.
pub(crate) struct InFlightLease(pub(crate) OwnedSemaphorePermit);

impl InFlightLease {
    pub(crate) fn new(permit: OwnedSemaphorePermit) -> Self {
        Self(permit)
    }
}

// ── AdmittedRequest ─────────────────────────────────────────────────────────

/// A request that has passed admission control, wrapped with its in-flight lease.
pub(crate) struct AdmittedRequest {
    pub(crate) request: RuntimeRequest,
    pub(crate) lease: InFlightLease,
}

// ── RuntimeRequest ──────────────────────────────────────────────────────────

/// All commands accepted at the ingress boundary.
pub(crate) enum RuntimeRequest {
    Create {
        context: ApplicationCommandContext,
        input: CreateTaskRunInput,
        reply: Reply,
    },
    Queue {
        context: ApplicationCommandContext,
        input: QueueTaskRunInput,
        reply: Reply,
    },
    Admit {
        context: ApplicationCommandContext,
        input: AdmitTaskRunInput,
        reply: Reply,
    },
    StartAttempt {
        context: ApplicationCommandContext,
        input: StartAttemptInput,
        reply: Reply,
    },
    Complete {
        context: ApplicationCommandContext,
        input: CompleteTaskRunInput,
        reply: Reply,
    },
}

impl RuntimeRequest {
    /// Extract the [`TaskRunId`] from the request, if applicable.
    /// Returns `None` for `Create` (which has no TaskRunId yet).
    pub(crate) fn taskrun_id(&self) -> Option<gocode_domain::id::TaskRunId> {
        match self {
            Self::Create { .. } => None,
            Self::Queue { input, .. } => Some(input.taskrun_id),
            Self::Admit { input, .. } => Some(input.taskrun_id),
            Self::StartAttempt { input, .. } => Some(input.taskrun_id),
            Self::Complete { input, .. } => Some(input.taskrun_id),
        }
    }
}

// ── PerRunRequest ───────────────────────────────────────────────────────────

/// Commands routed to a specific taskrun's worker mailbox.
pub(crate) enum PerRunRequest {
    Queue {
        context: ApplicationCommandContext,
        input: QueueTaskRunInput,
        reply: Reply,
    },
    Admit {
        context: ApplicationCommandContext,
        input: AdmitTaskRunInput,
        reply: Reply,
    },
    StartAttempt {
        context: ApplicationCommandContext,
        input: StartAttemptInput,
        reply: Reply,
    },
    Complete {
        context: ApplicationCommandContext,
        input: CompleteTaskRunInput,
        reply: Reply,
    },
}

impl PerRunRequest {
    /// Split the request into a callable command and the reply channel.
    pub(crate) fn into_parts(self) -> (PerRunCall, Reply) {
        match self {
            Self::Queue {
                context,
                input,
                reply,
            } => (PerRunCall::Queue { context, input }, reply),
            Self::Admit {
                context,
                input,
                reply,
            } => (PerRunCall::Admit { context, input }, reply),
            Self::StartAttempt {
                context,
                input,
                reply,
            } => (PerRunCall::StartAttempt { context, input }, reply),
            Self::Complete {
                context,
                input,
                reply,
            } => (PerRunCall::Complete { context, input }, reply),
        }
    }
}

// ── AdmittedPerRunRequest ───────────────────────────────────────────────────

/// A per-run request wrapped with its in-flight lease.
pub(crate) struct AdmittedPerRunRequest {
    pub(crate) request: PerRunRequest,
    pub(crate) lease: InFlightLease,
}

// ── PerRunCall ──────────────────────────────────────────────────────────────

/// A callable per-run command — reply channel already separated.
pub(crate) enum PerRunCall {
    Queue {
        context: ApplicationCommandContext,
        input: QueueTaskRunInput,
    },
    Admit {
        context: ApplicationCommandContext,
        input: AdmitTaskRunInput,
    },
    StartAttempt {
        context: ApplicationCommandContext,
        input: StartAttemptInput,
    },
    Complete {
        context: ApplicationCommandContext,
        input: CompleteTaskRunInput,
    },
}

impl PerRunCall {
    /// Execute the call against the given service (synchronous, for `spawn_blocking`).
    pub(crate) fn execute<E, U, I>(
        self,
        service: &TaskRunService<E, U, I>,
    ) -> Result<CommandOutcome, ApplicationError>
    where
        E: EventStore,
        U: UnitOfWork,
        I: IdGenerator,
    {
        match self {
            Self::Queue { context, input } => service.queue_task_run(&context, input),
            Self::Admit { context, input } => service.admit_task_run(&context, input),
            Self::StartAttempt { context, input } => service.start_attempt(&context, input),
            Self::Complete { context, input } => service.complete_task_run(&context, input),
        }
    }
}
