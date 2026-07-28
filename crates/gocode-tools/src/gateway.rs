use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use thiserror::Error;

use crate::{
    EffectAdmission, RawToolOutput, ToolDispatchBinding, ToolExecutionHandle, ToolExecutorError,
    ToolExecutorPort, ToolOutput, ToolOutputBounds,
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

impl<A, E> ToolGateway<A, E>
where
    A: ToolAdmissionPort,
    E: ToolExecutorPort,
{
    /// Constructs a gateway with exact output bounds.
    pub fn new(admission: A, executor: E, bounds: ToolOutputBounds) -> Self {
        Self {
            admission,
            executor,
            bounds,
            state: Mutex::new(BTreeMap::new()),
        }
    }

    /// Runs all gates in fixed order and returns no handle before effect admission.
    pub fn dispatch(
        &self,
        request: ToolDispatchRequest,
    ) -> Result<ToolExecutionHandle, ToolGatewayError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state.get(&request.invocation_id) {
            ensure_request(existing, &request)?;
            return existing
                .handle
                .clone()
                .ok_or(ToolGatewayError::UncertainAfterAdmission);
        }

        for stage in [
            GateStage::Capability,
            GateStage::Approval,
            GateStage::Budget,
            GateStage::Containment,
        ] {
            if self.admission.check(stage, &request)? != ToolAdmissionDecision::Passed {
                return Err(ToolAdmissionError::Unavailable.into());
            }
        }
        let effect = match self.admission.check(GateStage::EffectAdmission, &request)? {
            ToolAdmissionDecision::Winner(effect) => effect,
            ToolAdmissionDecision::Existing(handle) => {
                state.insert(
                    request.invocation_id,
                    InvocationState {
                        digest: request.request_digest,
                        binding: request.binding,
                        handle: Some(handle.clone()),
                        cancel_signalled: false,
                        terminal: None,
                    },
                );
                return Ok(handle);
            }
            ToolAdmissionDecision::Uncertain => {
                state.insert(
                    request.invocation_id,
                    InvocationState {
                        digest: request.request_digest,
                        binding: request.binding,
                        handle: None,
                        cancel_signalled: false,
                        terminal: Some(ToolTerminalDisposition::Uncertain),
                    },
                );
                return Err(ToolGatewayError::UncertainAfterAdmission);
            }
            ToolAdmissionDecision::Passed => {
                return Err(ToolAdmissionError::Unavailable.into());
            }
        };
        let handle = match self.executor.start(&request, &effect) {
            Ok(handle) => handle,
            Err(_) => {
                state.insert(
                    request.invocation_id,
                    InvocationState {
                        digest: request.request_digest,
                        binding: request.binding,
                        handle: None,
                        cancel_signalled: false,
                        terminal: Some(ToolTerminalDisposition::Uncertain),
                    },
                );
                return Err(ToolGatewayError::UncertainAfterAdmission);
            }
        };
        state.insert(
            request.invocation_id,
            InvocationState {
                digest: request.request_digest,
                binding: request.binding,
                handle: Some(handle.clone()),
                cancel_signalled: false,
                terminal: None,
            },
        );
        Ok(handle)
    }

    /// Durably identifies duplicate cancellation signals.
    pub fn signal_cancel(
        &self,
        request: ToolCancelRequest,
    ) -> Result<ToolCancelDisposition, ToolGatewayError> {
        let mut state = self.lock_state()?;
        let invocation =
            exact_invocation_mut(&mut state, &request.invocation_id, request.request_digest)?;
        ensure_handle(invocation, &request.handle)?;
        if invocation.cancel_signalled {
            return Ok(ToolCancelDisposition::AlreadySignalled);
        }
        let handle = invocation
            .handle
            .as_ref()
            .ok_or(ToolGatewayError::UncertainAfterAdmission)?;
        self.executor.signal_cancel(handle)?;
        invocation.cancel_signalled = true;
        Ok(ToolCancelDisposition::Signalled)
    }

    /// Produces the only terminal transition.
    pub fn close(
        &self,
        request: ToolCloseRequest,
    ) -> Result<ToolTerminalDisposition, ToolGatewayError> {
        let mut state = self.lock_state()?;
        let invocation =
            exact_invocation_mut(&mut state, &request.invocation_id, request.request_digest)?;
        ensure_handle(invocation, &request.handle)?;
        if let Some(terminal) = &invocation.terminal {
            return Ok(terminal.clone());
        }
        let terminal = if !request.evidence.is_complete() {
            ToolTerminalDisposition::Uncertain
        } else {
            match ToolOutput::bound(request.output, self.bounds) {
                Ok(output) => ToolTerminalDisposition::Completed(output),
                Err(()) => ToolTerminalDisposition::Uncertain,
            }
        };
        invocation.terminal = Some(terminal.clone());
        Ok(terminal)
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, InvocationState>>, ToolGatewayError> {
        self.state.lock().map_err(|_| ToolGatewayError::Unavailable)
    }
}

fn exact_invocation_mut<'a>(
    state: &'a mut BTreeMap<String, InvocationState>,
    invocation_id: &str,
    digest: [u8; 32],
) -> Result<&'a mut InvocationState, ToolGatewayError> {
    let invocation = state
        .get_mut(invocation_id)
        .ok_or(ToolGatewayError::ExecutionNotFound)?;
    ensure_digest(invocation, digest)?;
    Ok(invocation)
}

fn ensure_digest(invocation: &InvocationState, digest: [u8; 32]) -> Result<(), ToolGatewayError> {
    if invocation.digest == digest {
        Ok(())
    } else {
        Err(ToolGatewayError::DigestConflict)
    }
}

fn ensure_request(
    invocation: &InvocationState,
    request: &ToolDispatchRequest,
) -> Result<(), ToolGatewayError> {
    ensure_digest(invocation, request.request_digest)?;
    if invocation.binding == request.binding {
        Ok(())
    } else {
        Err(ToolGatewayError::AuthorityBindingConflict)
    }
}

fn ensure_handle(
    invocation: &InvocationState,
    handle: &ToolExecutionHandle,
) -> Result<(), ToolGatewayError> {
    if invocation.handle.as_ref() == Some(handle) {
        Ok(())
    } else {
        Err(ToolGatewayError::ExecutionNotFound)
    }
}
