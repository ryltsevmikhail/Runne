use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use thiserror::Error;

use crate::{
    EffectAdmission, RawToolOutput, ToolDispatchBinding, ToolExecutionHandle, ToolExecutorError,
    ProcessCompletion, ProtocolCompletion, ProtocolToolExecutorPort, ToolExecutorPort, ToolOutput,
    ToolOutputBounds,
};

/// Ordered pre-effect gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStage {
    /// Capability grant verification.
    Capability,
    /// Human or policy approval verification.
    Approval,
    /// Exact budget reservation verification.
    Budget,
    /// Certified containment verification.
    Containment,
    /// Atomic intent recording and permit claim.
    EffectAdmission,
}

/// Fail-closed admission failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolAdmissionError {
    /// A specific gate rejected the request.
    #[error("tool admission rejected at {0:?}")]
    Rejected(GateStage),
    /// Admission authority could not establish a decision.
    #[error("tool admission is unavailable")]
    Unavailable,
}

/// Ordered admission authority boundary.
pub trait ToolAdmissionPort: Send + Sync {
    /// Checks one exact stage and returns the durable disposition.
    fn check(
        &self,
        stage: GateStage,
        request: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError>;
}

/// Durable admission disposition, including restart/replay recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolAdmissionDecision {
    /// A pre-effect gate passed without claiming a permit.
    Passed,
    /// This caller atomically won the effect permit.
    Winner(EffectAdmission),
    /// Durable state proves the exact effect already has an execution handle.
    Existing(ToolExecutionHandle),
    /// A permit may have been consumed but no safe replay disposition is known.
    Uncertain,
}

/// Minimal exact dispatch identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDispatchRequest {
    /// Stable invocation identity.
    pub invocation_id: String,
    /// Canonical request digest.
    pub request_digest: [u8; 32],
    /// Exact authority binding revalidated at every admission stage.
    pub binding: ToolDispatchBinding,
}

/// Idempotent cancellation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCancelRequest {
    /// Stable invocation identity.
    pub invocation_id: String,
    /// Canonical request digest.
    pub request_digest: [u8; 32],
    /// Exact execution handle.
    pub handle: ToolExecutionHandle,
}

/// Evidence required for a successful terminal close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolCloseEvidence {
    /// Process tree reached a terminal state.
    pub process_terminal: bool,
    /// Containment resources were released.
    pub containment_released: bool,
    /// Cleanup authority closed all resources.
    pub cleanup_closed: bool,
}

/// Process-free terminal close request for a correlated protocol effect.
///
/// This tuple is deliberately not proof. The selected protocol executor is the
/// sole authority that validates its private terminal and settlement claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolProtocolCloseRequest {
    /// Stable invocation identity.
    pub invocation_id: String,
    /// Canonical request digest.
    pub request_digest: [u8; 32],
    /// Exact executor-owned execution handle.
    pub handle: ToolExecutionHandle,
}

impl ToolProtocolCloseRequest {
    /// Captures only the immutable dispatch tuple.
    pub fn new(
        invocation_id: String,
        request_digest: [u8; 32],
        handle: ToolExecutionHandle,
    ) -> Self {
        Self { invocation_id, request_digest, handle }
    }
}

impl ToolCloseEvidence {
    fn is_complete(self) -> bool {
        self.process_terminal && self.containment_released && self.cleanup_closed
    }
}

/// Terminal close request.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCloseRequest {
    /// Stable invocation identity.
    pub invocation_id: String,
    /// Canonical request digest.
    pub request_digest: [u8; 32],
    /// Exact execution handle.
    pub handle: ToolExecutionHandle,
    /// Process, containment and cleanup evidence.
    pub evidence: ToolCloseEvidence,
    /// Raw output subject to mandatory bounds.
    pub output: RawToolOutput,
}

/// Cancellation signal disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCancelDisposition {
    /// Signal was sent for the first time.
    Signalled,
    /// Exact cancellation request was already signalled.
    AlreadySignalled,
}

/// Only terminal gateway result.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolTerminalDisposition {
    /// Complete closure evidence and bounded output were recorded.
    Completed(ToolOutput),
    /// External state or cleanup could not be proven terminal.
    Uncertain,
}

/// Tool gateway failure before a trustworthy disposition exists.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolGatewayError {
    /// One admission stage failed before execution.
    #[error(transparent)]
    Admission(#[from] ToolAdmissionError),
    /// Same invocation identity was reused with different bytes.
    #[error("tool invocation digest conflict")]
    DigestConflict,
    /// Same invocation identity was reused with a different authority binding.
    #[error("tool invocation authority binding conflict")]
    AuthorityBindingConflict,
    /// Invocation or execution handle was not found.
    #[error("tool execution was not found")]
    ExecutionNotFound,
    /// Executor rejected or could not service a pre-effect operation.
    #[error(transparent)]
    Executor(#[from] ToolExecutorError),
    /// Gateway state lock is unavailable.
    #[error("tool gateway state is unavailable")]
    Unavailable,
    /// A permit was claimed but execution outcome is ambiguous.
    #[error("tool execution is uncertain after effect admission")]
    UncertainAfterAdmission,
    /// A protocol closure replay changed evidence or settlement binding.
    #[error("tool protocol closure binding conflict")]
    ProtocolClosureConflict,
}

#[derive(Debug, Clone)]
struct InvocationState {
    digest: [u8; 32],
    binding: ToolDispatchBinding,
    handle: Option<ToolExecutionHandle>,
    cancel_signalled: bool,
    terminal: Option<ToolTerminalDisposition>,
}

/// Fail-closed ordered tool execution gateway.
pub struct ToolGateway<A, E> {
    admission: A,
    executor: E,
    bounds: ToolOutputBounds,
    state: Mutex<BTreeMap<String, InvocationState>>,
}
