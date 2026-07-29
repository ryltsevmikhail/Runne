use thiserror::Error;

use crate::ToolDispatchRequest;

/// Durable effect admission returned immediately before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectAdmission {
    /// Exact claimed permit identity.
    pub permit_id: String,
}

/// Opaque execution identity returned by the selected executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionHandle {
    /// Exact executor-owned identity.
    pub execution_id: String,
}

/// Executor boundary failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolExecutorError {
    /// The selected executor is unavailable.
    #[error("tool executor is unavailable")]
    Unavailable,
    /// The structured request was rejected.
    #[error("tool executor rejected the request")]
    Rejected,
}

/// Runtime-neutral selected tool executor boundary.
pub trait ToolExecutorPort: Send + Sync {
    /// Starts external work only after exact effect admission.
    fn start(
        &self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError>;

    /// Sends a cooperative cancellation signal.
    fn signal_cancel(&self, handle: &ToolExecutionHandle) -> Result<(), ToolExecutorError>;
}
