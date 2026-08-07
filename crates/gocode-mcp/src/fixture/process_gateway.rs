use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use gocode_tools::{
    ProcessAuthorizationAuthorityV1, ProcessContractHostV1, ProcessLifecycleStateV1,
    SandboxQualificationProbe, ToolGateway, ToolOutputBounds,
};

use super::process::ProcessTerminalRecord;
use crate::discovery::McpGenerationAdvance;
use crate::{McpDispatchBinding, McpGenerationAdvanceError, McpGenerationAuthority};

mod admission;
mod dispatch;
mod terminal;

use admission::ProcessAdmission;
use dispatch::{GateFailure, HostOutcomes, PendingCalls};
pub use dispatch::{McpProcessExecutor, McpProcessGatewayError};

/// MCP gateway that mediates process-backed tools through the process contract only.
pub struct McpProcessToolGateway {
    gateway: ToolGateway<ProcessAdmission, McpProcessExecutor>,
    generation: Arc<McpGenerationAuthority>,
    pending: PendingCalls,
    failures: Arc<Mutex<BTreeMap<String, GateFailure>>>,
    outcomes: HostOutcomes,
    effects: Arc<AtomicUsize>,
    terminals: Mutex<BTreeMap<String, ProcessTerminalRecord>>,
}

impl McpProcessToolGateway {
    /// Composes one shared authority, qualified probe and exclusive process host.
    #[must_use]
    pub fn new(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        generation: Arc<McpGenerationAuthority>,
        bounds: ToolOutputBounds,
    ) -> Self {
        Self::compose(authority, host, probe, generation, bounds)
    }

    fn compose(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        generation: Arc<McpGenerationAuthority>,
        bounds: ToolOutputBounds,
    ) -> Self {
        let pending = Arc::new(Mutex::new(BTreeMap::new()));
        let failures = Arc::new(Mutex::new(BTreeMap::new()));
        let outcomes = Arc::new(Mutex::new(BTreeMap::new()));
        let effects = Arc::new(AtomicUsize::new(0));
        let admission = ProcessAdmission {
            authority,
            probe,
            pending: Arc::clone(&pending),
            failures: Arc::clone(&failures),
            effects: Arc::clone(&effects),
        };
        let executor = McpProcessExecutor {
            pending: Arc::clone(&pending),
            host: Arc::new(Mutex::new(host)),
            outcomes: Arc::clone(&outcomes),
        };
        Self {
            gateway: ToolGateway::new(admission, executor, bounds),
            generation,
            pending,
            failures,
            outcomes,
            effects,
            terminals: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the closed lifecycle state retained under the invocation handle.
    pub fn host_outcome(&self, invocation_id: &str) -> Option<ProcessLifecycleStateV1> {
        let key = format!("mcp-process:{invocation_id}");
        let outcomes = self.outcomes.lock().ok()?;
        match outcomes.get(&key) {
            Some(gocode_tools::ProcessHostOutcomeV1::State(state)) => Some(*state),
            _ => None,
        }
    }

    /// Returns the number of calls that reached the sole effect-admission authority.
    pub fn effect_admission_count(&self) -> usize {
        self.effects.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn test_state_counts(&self) -> Option<(usize, usize, usize, usize)> {
        Some((
            self.pending.lock().ok()?.len(),
            self.terminals.lock().ok()?.len(),
            self.failures.lock().ok()?.len(),
            self.outcomes.lock().ok()?.len(),
        ))
    }

    pub(crate) fn prepare_generation_advance(
        &self,
        expected_generation: u64,
        binding: &McpDispatchBinding,
    ) -> Result<McpGenerationAdvance<'_>, McpGenerationAdvanceError> {
        let advance = self.generation.prepare_advance(binding)?;
        if advance.current_generation() != expected_generation {
            return Err(McpGenerationAdvanceError::InvalidGeneration);
        }
        Ok(advance)
    }

    #[cfg(test)]
    pub(super) fn generation_for_test(&self) -> Arc<McpGenerationAuthority> {
        Arc::clone(&self.generation)
    }
}
