use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, SyncSender},
};

use gocode_tools::{
    ProcessAuthorizationAuthorityV1, ProcessContractHostV1, SandboxQualificationProbe, ToolGateway,
    ToolOutputBounds,
};

use crate::{McpDispatchBinding, McpGenerationAdvanceError, McpGenerationAuthority};

use super::process_call::{ClaimedProcessCall, ProcessDispatchPayload, VerifiedProcessCall};
use super::runtime::process_ledger::{
    FixtureProcessLedgerPort, ProcessPhaseOutcome, ProcessReservationReceipt,
};

mod admission;
mod dispatch;
#[cfg(test)]
pub(in crate::fixture) mod ledger_port;
mod terminal;

#[cfg(test)]
pub(in crate::fixture) use admission::ProcessGateFault;

use admission::{Failures, ProcessAdmission};
pub(in crate::fixture) use dispatch::McpProcessExecutor;
use dispatch::{HostOutcomes, PendingCalls};

pub(in crate::fixture) struct McpProcessToolGateway {
    gateway: ToolGateway<ProcessAdmission, McpProcessExecutor>,
    generation: Arc<McpGenerationAuthority>,
    pending: PendingCalls,
    outcomes: HostOutcomes,
    #[cfg(test)]
    effects: Arc<AtomicUsize>,
    #[cfg(test)]
    host_dispatches: Arc<AtomicUsize>,
    ledger: Arc<FixtureProcessLedgerPort>,
    failures: Failures,
    #[cfg(test)]
    fault: Option<admission::ProcessGateFault>,
    #[cfg(test)]
    settlement_fence: Arc<Mutex<Option<SettlementFence>>>,
}

#[cfg(test)]
struct SettlementFence {
    settled: SyncSender<()>,
    release: Receiver<()>,
}

impl McpProcessToolGateway {
    pub(in crate::fixture) fn new(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        generation: Arc<McpGenerationAuthority>,
        ledger: Arc<FixtureProcessLedgerPort>,
        bounds: ToolOutputBounds,
    ) -> Self {
        let pending = Arc::new(Mutex::new(Default::default()));
        let outcomes = Arc::new(Mutex::new(Default::default()));
        #[cfg(test)]
        let effects = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let host_dispatches = Arc::new(AtomicUsize::new(0));
        #[cfg(test)]
        let settlement_fence = Arc::new(Mutex::new(None));
        let failures = Arc::new(Mutex::new(Default::default()));
        let admission = ProcessAdmission::new(
            authority,
            probe,
            Arc::clone(&pending),
            #[cfg(test)]
            Arc::clone(&effects),
            Arc::clone(&failures),
            Arc::clone(&ledger),
        );
        let executor = McpProcessExecutor {
            pending: Arc::clone(&pending),
            host: Arc::new(Mutex::new(host)),
            outcomes: Arc::clone(&outcomes),
            #[cfg(test)]
            host_dispatches: Arc::clone(&host_dispatches),
        };
        Self {
            gateway: ToolGateway::new(admission, executor, bounds),
            generation,
            pending,
            outcomes,
            #[cfg(test)]
            effects,
            #[cfg(test)]
            host_dispatches,
            ledger,
            failures,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            settlement_fence,
        }
    }

    pub(in crate::fixture) fn verify_c2b(
        payload: &ProcessDispatchPayload,
    ) -> Result<VerifiedProcessCall, McpProcessGatewayError> {
        payload
            .mcp()
            .verify_c2b(payload.material().intent())
            .map_err(McpProcessGatewayError::from)?;
        let (binding, request) = payload.mcp().verified_process_call();
        Ok(VerifiedProcessCall::new(request, binding))
    }

    pub(in crate::fixture) fn claim_verified(
        &self,
        verified: VerifiedProcessCall,
    ) -> Result<ClaimedProcessCall<'_>, McpProcessGatewayError> {
        let permit = self
            .generation
            .claim_dispatch(verified.binding())
            .map_err(|_| McpProcessGatewayError::StaleGeneration)?;
        if !permit.matches(verified.binding()) {
            return Err(McpProcessGatewayError::InvalidBinding);
        }
        Ok(ClaimedProcessCall::new(verified, permit))
    }

    pub(in crate::fixture) fn dispatch_claimed(
        &self,
        claimed: ClaimedProcessCall<'_>,
        receipt: ProcessReservationReceipt,
        payload: ProcessDispatchPayload,
    ) -> ProcessPhaseOutcome {
        dispatch::dispatch_claimed(self, claimed, receipt, payload)
    }

    #[cfg(test)]
    pub(super) fn effect_admission_count(&self) -> usize {
        self.effects.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn host_dispatch_count_for_test(&self) -> usize {
        self.host_dispatches.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn pause_after_settlement_for_test(
        &self,
        settled: SyncSender<()>,
        release: Receiver<()>,
    ) {
        *self.settlement_fence.lock().unwrap() = Some(SettlementFence { settled, release });
    }

    #[cfg(test)]
    pub(super) fn wait_after_settlement_for_test(&self) {
        let fence = self
            .settlement_fence
            .lock()
            .ok()
            .and_then(|mut fence| fence.take());
        if let Some(fence) = fence {
            fence.settled.send(()).unwrap();
            fence.release.recv().unwrap();
        }
    }

    pub(in crate::fixture) fn prepare_generation_advance(
        &self,
        expected_generation: u64,
        binding: &McpDispatchBinding,
    ) -> Result<crate::discovery::McpGenerationAdvance<'_>, McpGenerationAdvanceError> {
        let advance = self.generation.prepare_advance(binding)?;
        (advance.current_generation() == expected_generation)
            .then_some(advance)
            .ok_or(McpGenerationAdvanceError::InvalidGeneration)
    }

    #[cfg(test)]
    pub(super) fn generation_for_test(&self) -> Arc<McpGenerationAuthority> {
        Arc::clone(&self.generation)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn dispatch_for_test(
        &self,
        runtime: &super::runtime::FixtureMcpRuntime,
        key: super::process_call::ProcessEffectKey,
        payload: ProcessDispatchPayload,
    ) -> Result<ProcessPhaseOutcome, ledger_port::TestDispatchError> {
        ledger_port::dispatch_for_test(self, runtime, key, payload)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn dispatch_reserved_for_test(
        &self,
        receipt: ProcessReservationReceipt,
        payload: ProcessDispatchPayload,
    ) -> Result<ProcessPhaseOutcome, ledger_port::TestDispatchError> {
        ledger_port::dispatch_reserved_for_test(self, receipt, payload)
    }

    #[cfg(test)]
    pub(in crate::fixture) fn new_with_fault_for_test(
        authority: ProcessAuthorizationAuthorityV1,
        host: ProcessContractHostV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        generation: Arc<McpGenerationAuthority>,
        ledger: Arc<FixtureProcessLedgerPort>,
        bounds: ToolOutputBounds,
        fault: admission::ProcessGateFault,
    ) -> Self {
        let pending = Arc::new(Mutex::new(Default::default()));
        let outcomes = Arc::new(Mutex::new(Default::default()));
        let effects = Arc::new(AtomicUsize::new(0));
        let host_dispatches = Arc::new(AtomicUsize::new(0));
        let settlement_fence = Arc::new(Mutex::new(None));
        let failures = Arc::new(Mutex::new(Default::default()));
        let admission = ProcessAdmission::new_with_fault(
            authority,
            probe,
            Arc::clone(&pending),
            Arc::clone(&effects),
            Arc::clone(&failures),
            Arc::clone(&ledger),
            fault,
        );
        let executor = McpProcessExecutor {
            pending: Arc::clone(&pending),
            host: Arc::new(Mutex::new(host)),
            outcomes: Arc::clone(&outcomes),
            host_dispatches: Arc::clone(&host_dispatches),
        };
        Self {
            gateway: ToolGateway::new(admission, executor, bounds),
            generation,
            pending,
            outcomes,
            effects,
            host_dispatches,
            ledger,
            failures,
            fault: Some(fault),
            settlement_fence,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::fixture) enum McpProcessGatewayError {
    ExecutionClassMismatch,
    ProcessIntentRequired,
    ProcessIntentMismatch,
    InvalidBinding,
    StaleGeneration,
}

impl From<crate::discovery::ProcessCallBindingError> for McpProcessGatewayError {
    fn from(error: crate::discovery::ProcessCallBindingError) -> Self {
        match error {
            crate::discovery::ProcessCallBindingError::ExecutionClassMismatch => {
                Self::ExecutionClassMismatch
            }
            crate::discovery::ProcessCallBindingError::ProcessIntentRequired => {
                Self::ProcessIntentRequired
            }
            crate::discovery::ProcessCallBindingError::ProcessIntentMismatch => {
                Self::ProcessIntentMismatch
            }
            crate::discovery::ProcessCallBindingError::InvalidBinding => Self::InvalidBinding,
        }
    }
}
