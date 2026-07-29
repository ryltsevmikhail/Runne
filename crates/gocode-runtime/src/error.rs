//! Typed runtime errors — closed, machine-distinguishable.

use core::fmt;

use gocode_application::conversation_text_service::ConversationTextServiceError;
use gocode_application::errors::ApplicationError;
use gocode_domain::id::TaskRunId;

/// Which queue rejected the request due to backpressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueKind {
    /// The global ingress channel is full.
    Ingress,
    /// A per-taskrun mailbox is full.
    TaskRun,
    /// No blocking pool permits are available.
    BlockingPool,
}

/// How a worker failed during execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerFailureKind {
    /// The blocking pool (tokio spawn_blocking) was closed.
    BlockingPoolClosed,
    /// The spawned task panicked.
    WorkerPanicked,
    /// The reply oneshot channel was already closed by the caller.
    ReplyChannelClosed,
}

/// All runtime-level errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// A queue rejected the request due to capacity limits.
    Backpressure {
        /// Which queue was full.
        queue: QueueKind,
    },
    /// The runtime has been closed (draining or shut down).
    RuntimeClosed,
    /// A worker failed during execution of a taskrun command.
    WorkerExecutionFailed {
        /// The taskrun that was being processed, if known.
        taskrun_id: Option<TaskRunId>,
        /// How the worker failed.
        kind: WorkerFailureKind,
    },
    /// An application-level error occurred.
    Application(ApplicationError),
    /// A Conversation text coordinator rejected or failed the command.
    ConversationApplication(ConversationTextServiceError),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backpressure { queue } => {
                write!(f, "backpressure: {:?} queue is full", queue)
            }
            Self::RuntimeClosed => {
                write!(f, "runtime is closed")
            }
            Self::WorkerExecutionFailed { taskrun_id, kind } => {
                write!(
                    f,
                    "worker execution failed for taskrun {:?}: {:?}",
                    taskrun_id, kind
                )
            }
            Self::Application(e) => write!(f, "application error: {}", e),
            Self::ConversationApplication(error) => {
                write!(f, "conversation application error: {error:?}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<ApplicationError> for RuntimeError {
    fn from(e: ApplicationError) -> Self {
        Self::Application(e)
    }
}
