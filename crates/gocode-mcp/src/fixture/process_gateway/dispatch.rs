use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use gocode_tools::{
    EffectAdmission, ProcessApprovalV1, ProcessCapabilityV1, ProcessContractError,
    ProcessContractHostV1, ProcessHostOutcomeV1, ProcessLifecycleBindingV1, ProcessStubDisposition,
    ProcessToolExecutorPort, ToolDispatchRequest, ToolExecutionHandle, ToolExecutorError,
    ToolExecutorPort, ToolGatewayError,
};

use super::super::process::ProcessTerminalReplay;
use super::McpProcessToolGateway;
use crate::{McpProcessCall, discovery::ProcessCallBindingError};

pub(super) struct PendingProcessCall {
    pub(super) digest: [u8; 32],
    pub(super) intent: gocode_tools::ProcessIntentV1,
    pub(super) capability: Option<ProcessCapabilityV1>,
    pub(super) approval: Option<ProcessApprovalV1>,
    pub(super) now: u64,
    pub(super) lifecycle: ProcessLifecycleBindingV1,
    pub(super) binding_digest: [u8; 32],
    pub(super) validated: Option<gocode_tools::ValidatedProcessIntentV1>,
}
pub(super) type PendingCalls = Arc<Mutex<BTreeMap<String, PendingProcessCall>>>;
pub(super) type HostOutcomes = Arc<Mutex<BTreeMap<String, ProcessHostOutcomeV1>>>;

pub(super) enum GateFailure {
    Authorization(ProcessContractError),
    InvalidBinding,
    Sandbox(ProcessStubDisposition),
}

/// Process executor that has only process-lifecycle terminal authority.
pub struct McpProcessExecutor {
    pub(super) pending: PendingCalls,
    pub(super) host: Arc<Mutex<ProcessContractHostV1>>,
    pub(super) outcomes: HostOutcomes,
}

impl ToolExecutorPort for McpProcessExecutor {
    type CompletionMode = gocode_tools::ProcessCompletion;

    fn start(
        &self,
        request: &ToolDispatchRequest,
        admission: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError> {
        if admission.permit_id.is_empty() {
            return Err(ToolExecutorError::Rejected);
        }
        let intent = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| ToolExecutorError::Unavailable)?;
            let call = pending
                .get_mut(&request.invocation_id)
                .ok_or(ToolExecutorError::Rejected)?;
            if call.digest != request.request_digest {
                return Err(ToolExecutorError::Rejected);
            }
            call.validated.take().ok_or(ToolExecutorError::Rejected)?
        };
        let handle = ToolExecutionHandle {
            execution_id: format!("mcp-process:{}", request.invocation_id),
        };
        let outcome = self
            .host
            .lock()
            .map_err(|_| ToolExecutorError::Unavailable)?
            .dispatch(intent, admission)
            .map_err(|_| ToolExecutorError::Rejected)?;
        self.outcomes
            .lock()
            .map_err(|_| ToolExecutorError::Unavailable)?
            .insert(handle.execution_id.clone(), outcome);
        Ok(handle)
    }

    fn signal_cancel(&self, _: &ToolExecutionHandle) -> Result<(), ToolExecutorError> {
        Err(ToolExecutorError::Rejected)
    }
}

impl ProcessToolExecutorPort for McpProcessExecutor {}

/// Typed result for a process-backed MCP dispatch.
#[derive(Debug, PartialEq, Eq)]
pub enum McpProcessGatewayError {
    /// The capability execution class is not process-backed.
    ExecutionClassMismatch,
    /// The capability lacks the required exact process intent digest.
    ProcessIntentRequired,
    /// The capability digest does not bind the carried process intent.
    ProcessIntentMismatch,
    /// The immutable MCP binding is stale or inconsistent.
    InvalidBinding,
    /// The authoritative MCP generation no longer matches.
    StaleGeneration,
    /// Process authorization rejected opaque capability or approval material.
    Authorization(ProcessContractError),
    /// Production sandbox qualification rejected before an effect permit.
    Sandbox(ProcessStubDisposition),
    /// Effect admission crossed a boundary whose closed host is uncertain.
    Uncertain,
    /// An internal gateway failure did not expose authorization material.
    Gateway(ToolGatewayError),
    /// Pending process state was unavailable.
    Unavailable,
}

impl McpProcessToolGateway {
    /// Runs the exact process admission sequence without a protocol fallback.
    pub fn dispatch(
        &self,
        call: McpProcessCall,
    ) -> Result<ToolExecutionHandle, McpProcessGatewayError> {
        call.capability
            .verify_c2b(&call.intent)
            .map_err(map_c2b_error)?;
        let (binding, _, request, lifecycle, _) = call.capability.into_process_parts();
        let permit = self
            .generation
            .claim_dispatch(&binding)
            .map_err(|_| McpProcessGatewayError::StaleGeneration)?;
        if !permit.matches(&binding) {
            return Err(McpProcessGatewayError::InvalidBinding);
        }
        if let Some(record) = self
            .terminals
            .lock()
            .map_err(|_| McpProcessGatewayError::Unavailable)?
            .get(&request.invocation_id)
        {
            return match record.replay(request.request_digest) {
                ProcessTerminalReplay::Completed(handle) => Ok(handle),
                ProcessTerminalReplay::Uncertain => Err(McpProcessGatewayError::Uncertain),
                ProcessTerminalReplay::DigestConflict => {
                    Err(McpProcessGatewayError::InvalidBinding)
                }
            };
        }
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| McpProcessGatewayError::Unavailable)?;
            match pending.entry(request.invocation_id.clone()) {
                std::collections::btree_map::Entry::Occupied(existing) => {
                    let existing = existing.get();
                    if existing.digest != request.request_digest
                        || existing.binding_digest != binding.binding_digest()
                    {
                        return Err(McpProcessGatewayError::InvalidBinding);
                    }
                    return Err(McpProcessGatewayError::Unavailable);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(PendingProcessCall {
                        digest: request.request_digest,
                        intent: call.intent,
                        capability: call.process_capability,
                        approval: call.approval,
                        now: call.now,
                        lifecycle,
                        binding_digest: binding.binding_digest(),
                        validated: None,
                    });
                }
            };
        }
        let result = match self.gateway.dispatch(request.clone()) {
            Ok(handle) => self.settle_host_outcome(&request, handle),
            Err(error) => match self.take_failure(&request.invocation_id) {
                Some(failure) => Err(failure),
                None if error == ToolGatewayError::UncertainAfterAdmission => self
                    .record_uncertain(&request)
                    .and(Err(McpProcessGatewayError::Uncertain)),
                None => Err(McpProcessGatewayError::Gateway(error)),
            },
        };
        self.remove_pending(&request.invocation_id)?;
        result
    }
}

fn map_c2b_error(error: ProcessCallBindingError) -> McpProcessGatewayError {
    match error {
        ProcessCallBindingError::ExecutionClassMismatch => {
            McpProcessGatewayError::ExecutionClassMismatch
        }
        ProcessCallBindingError::ProcessIntentRequired => {
            McpProcessGatewayError::ProcessIntentRequired
        }
        ProcessCallBindingError::ProcessIntentMismatch => {
            McpProcessGatewayError::ProcessIntentMismatch
        }
        ProcessCallBindingError::InvalidBinding => McpProcessGatewayError::InvalidBinding,
    }
}
