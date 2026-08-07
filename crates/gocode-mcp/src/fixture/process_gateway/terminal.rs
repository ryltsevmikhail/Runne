use gocode_tools::{
    ProcessHostOutcomeV1, ProcessLifecycleStateV1, RawToolOutput, ToolCloseEvidence,
    ToolCloseRequest, ToolDispatchRequest, ToolExecutionHandle, ToolTerminalDisposition,
};

use super::super::process::{ProcessTerminalRecord, ProcessTerminalReplay};
use super::{GateFailure, McpProcessGatewayError, McpProcessToolGateway};

impl McpProcessToolGateway {
    pub(super) fn settle_host_outcome(
        &self,
        request: &ToolDispatchRequest,
        handle: ToolExecutionHandle,
    ) -> Result<ToolExecutionHandle, McpProcessGatewayError> {
        let key = format!("mcp-process:{}", request.invocation_id);
        let outcome = self
            .outcomes
            .lock()
            .map_err(|_| McpProcessGatewayError::Unavailable)?
            .remove(&key);
        match outcome {
            Some(ProcessHostOutcomeV1::Terminal(_)) => match self
                .gateway
                .close(ToolCloseRequest {
                    invocation_id: request.invocation_id.clone(),
                    request_digest: request.request_digest,
                    handle: handle.clone(),
                    evidence: ToolCloseEvidence {
                        process_terminal: true,
                        containment_released: true,
                        cleanup_closed: true,
                    },
                    output: RawToolOutput::default(),
                })
                .map_err(McpProcessGatewayError::Gateway)?
            {
                ToolTerminalDisposition::Completed(_) => {
                    self.record_completed(request, &handle)?;
                    Ok(handle)
                }
                ToolTerminalDisposition::Uncertain => self.mark_uncertain(request, &handle),
            },
            Some(ProcessHostOutcomeV1::State(state)) => {
                self.outcomes
                    .lock()
                    .map_err(|_| McpProcessGatewayError::Unavailable)?
                    .insert(key, ProcessHostOutcomeV1::State(state));
                if state == ProcessLifecycleStateV1::Uncertain {
                    self.mark_uncertain(request, &handle)
                } else {
                    Ok(handle)
                }
            }
            Some(ProcessHostOutcomeV1::Denied) | None => self.mark_uncertain(request, &handle),
        }
    }

    fn mark_uncertain(
        &self,
        request: &ToolDispatchRequest,
        handle: &ToolExecutionHandle,
    ) -> Result<ToolExecutionHandle, McpProcessGatewayError> {
        self.gateway
            .mark_uncertain(&request.invocation_id, request.request_digest, handle)
            .map_err(McpProcessGatewayError::Gateway)?;
        self.record_uncertain(request)?;
        Err(McpProcessGatewayError::Uncertain)
    }

    fn record_completed(
        &self,
        request: &ToolDispatchRequest,
        handle: &ToolExecutionHandle,
    ) -> Result<(), McpProcessGatewayError> {
        self.record_terminal(
            request,
            ProcessTerminalRecord::completed(request.request_digest, handle.clone()),
        )
    }

    pub(super) fn record_uncertain(
        &self,
        request: &ToolDispatchRequest,
    ) -> Result<(), McpProcessGatewayError> {
        self.record_terminal(
            request,
            ProcessTerminalRecord::uncertain(request.request_digest),
        )
    }

    fn record_terminal(
        &self,
        request: &ToolDispatchRequest,
        record: ProcessTerminalRecord,
    ) -> Result<(), McpProcessGatewayError> {
        let mut terminals = self
            .terminals
            .lock()
            .map_err(|_| McpProcessGatewayError::Unavailable)?;
        match terminals.get(&request.invocation_id) {
            None => {
                terminals.insert(request.invocation_id.clone(), record);
                Ok(())
            }
            Some(existing) if existing == &record => Ok(()),
            Some(existing)
                if matches!(
                    existing.replay(request.request_digest),
                    ProcessTerminalReplay::DigestConflict
                ) =>
            {
                Err(McpProcessGatewayError::InvalidBinding)
            }
            Some(_) => Err(McpProcessGatewayError::Unavailable),
        }
    }

    pub(super) fn take_failure(&self, invocation: &str) -> Option<McpProcessGatewayError> {
        match self.failures.lock().ok()?.remove(invocation)? {
            GateFailure::Authorization(error) => Some(McpProcessGatewayError::Authorization(error)),
            GateFailure::InvalidBinding => Some(McpProcessGatewayError::InvalidBinding),
            GateFailure::Sandbox(disposition) => Some(McpProcessGatewayError::Sandbox(disposition)),
        }
    }

    pub(super) fn remove_pending(&self, invocation: &str) -> Result<(), McpProcessGatewayError> {
        self.pending
            .lock()
            .map_err(|_| McpProcessGatewayError::Unavailable)?
            .remove(invocation);
        Ok(())
    }
}
