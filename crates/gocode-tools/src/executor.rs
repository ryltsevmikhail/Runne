use thiserror::Error;

use crate::{ToolDispatchRequest, ToolProtocolCloseRequest};

/// Terminal authority selected by one concrete tool executor.
pub trait CompletionMode: Send + Sync {}

/// Process lifecycle evidence is the sole terminal authority.
pub struct ProcessCompletion;

impl CompletionMode for ProcessCompletion {}

/// Correlated protocol proof is the sole terminal authority.
pub struct ProtocolCompletion;

impl CompletionMode for ProtocolCompletion {}

/// Executor has no terminal completion operation.
pub struct NoTerminalCompletion;

impl CompletionMode for NoTerminalCompletion {}

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
    /// Mutually exclusive terminal authority selected by this executor.
    type CompletionMode: CompletionMode;

    /// Starts external work only after exact effect admission.
    fn start(
        &self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError>;

    /// Sends a cooperative cancellation signal.
    fn signal_cancel(&self, handle: &ToolExecutionHandle) -> Result<(), ToolExecutorError>;
}

/// Marker for executors whose effects are closed with process lifecycle evidence.
///
/// ```compile_fail
/// use gocode_tools::{ProcessToolExecutorPort, ToolAdmissionPort, ToolGateway, ToolProtocolCloseRequest};
///
/// fn cannot_close_protocol<A: ToolAdmissionPort, E: ProcessToolExecutorPort>(gateway: &ToolGateway<A, E>, request: ToolProtocolCloseRequest) {
///     let _ = gateway.close_protocol(request);
/// }
/// ```
///
/// A concrete executor must select one terminal authority: process or protocol.
pub trait ProcessToolExecutorPort: ToolExecutorPort<CompletionMode = ProcessCompletion> {}

/// Marker for executors whose effects are closed by correlated protocol proof.
///
/// ```compile_fail
/// use gocode_tools::{ProtocolToolExecutorPort, ToolAdmissionPort, ToolCloseRequest, ToolGateway};
///
/// fn cannot_close_process<A: ToolAdmissionPort, E: ProtocolToolExecutorPort>(gateway: &ToolGateway<A, E>, request: ToolCloseRequest) {
///     let _ = gateway.close(request);
/// }
/// ```
///
/// Implementors retain the private terminal and settlement claim; callers can
/// supply only the immutable dispatch tuple.
pub trait ProtocolToolExecutorPort: ToolExecutorPort<CompletionMode = ProtocolCompletion> {
    /// Confirms an executor-owned terminal and settlement claim for this tuple.
    fn confirm_protocol_completion(
        &self,
        request: &ToolProtocolCloseRequest,
    ) -> Result<(), ToolExecutorError>;
}
