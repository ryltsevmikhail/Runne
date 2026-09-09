#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use runne_tools::{
    EffectAdmission, GateStage, ProcessAuthorizationAuthorityV1, SandboxQualificationProbe,
    ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort, ToolDispatchRequest,
};

use super::super::runtime::process_ledger::{
    FixtureProcessLedgerPort, PendingProcessCall, ProcessLedgerError, ProcessPreEffectFailure,
};
use super::PendingCalls;

pub(super) type Failures = Arc<Mutex<BTreeMap<String, ProcessPreEffectFailure>>>;

pub(super) struct ProcessAdmission {
    authority: ProcessAuthorizationAuthorityV1,
    probe: Arc<dyn SandboxQualificationProbe>,
    pending: PendingCalls,
    failures: Failures,
    #[cfg(test)]
    effects: Arc<AtomicUsize>,
    ledger: Arc<FixtureProcessLedgerPort>,
    #[cfg(test)]
    fault: Option<ProcessGateFault>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(in crate::fixture) enum ProcessGateFault {
    BudgetDenied,
    EffectUncertain,
    Uncertain(super::super::runtime::process_ledger::ProcessUncertainReason),
    PanicFinalValidation,
    PanicWitnessAssignment,
    PanicCommit,
}

impl ProcessAdmission {
    pub(super) fn new(
        authority: ProcessAuthorizationAuthorityV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        pending: PendingCalls,
        #[cfg(test)] effects: Arc<AtomicUsize>,
        failures: Failures,
        ledger: Arc<FixtureProcessLedgerPort>,
    ) -> Self {
        Self {
            authority,
            probe,
            pending,
            #[cfg(test)]
            effects,
            ledger,
            failures,
            #[cfg(test)]
            fault: None,
        }
    }

    #[cfg(test)]
    pub(super) fn new_with_fault(
        authority: ProcessAuthorizationAuthorityV1,
        probe: Arc<dyn SandboxQualificationProbe>,
        pending: PendingCalls,
        effects: Arc<AtomicUsize>,
        failures: Failures,
        ledger: Arc<FixtureProcessLedgerPort>,
        fault: ProcessGateFault,
    ) -> Self {
        let mut admission = Self::new(authority, probe, pending, effects, failures, ledger);
        admission.fault = Some(fault);
        admission
    }

    fn reject(
        &self,
        request: &ToolDispatchRequest,
        stage: GateStage,
        failure: ProcessPreEffectFailure,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        self.failures
            .lock()
            .map_err(|_| ToolAdmissionError::Unavailable)?
            .insert(request.invocation_id.clone(), failure);
        Err(ToolAdmissionError::Rejected(stage))
    }

    fn pending_call<T>(
        &self,
        request: &ToolDispatchRequest,
        action: impl FnOnce(&mut PendingProcessCall) -> Result<T, ProcessPreEffectFailure>,
    ) -> Result<T, ProcessPreEffectFailure> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| ProcessPreEffectFailure::GatewayUnavailable)?;
        let call = pending
            .get_mut(&request.invocation_id)
            .ok_or(ProcessPreEffectFailure::GatewayUnavailable)?;
        (call.admission_evidence().request_digest() == request.request_digest)
            .then_some(())
            .ok_or(ProcessPreEffectFailure::CapabilityPreflight)?;
        action(call)
    }
}

impl ToolAdmissionPort for ProcessAdmission {
    fn check(
        &self,
        stage: GateStage,
        request: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        match stage {
            GateStage::Capability => {
                let outcome = self.pending_call(request, |call| {
                    self.authority
                        .bind_call(call.material().intent().lifecycle_binding())
                        .and_then(|boundary| {
                            boundary.preflight_authorization(
                                call.material().intent(),
                                Some(call.material().capability()),
                                Some(call.material().approval()),
                                call.material().issued_at(),
                            )
                        })
                        .map_err(|_| ProcessPreEffectFailure::Authorization)
                });
                outcome
                    .map(|_| ToolAdmissionDecision::Passed)
                    .or_else(|failure| self.reject(request, stage, failure))
            }
            GateStage::Approval => Ok(ToolAdmissionDecision::Passed),
            GateStage::Budget => {
                #[cfg(test)]
                if matches!(self.fault, Some(ProcessGateFault::BudgetDenied)) {
                    return self.reject(request, stage, ProcessPreEffectFailure::Budget);
                }
                let outcome = self.pending_call(request, |call| {
                    self.ledger
                        .verify_reserved(&call.identity())
                        .map_err(|error| match error {
                            ProcessLedgerError::ReceiptNotReserved
                            | ProcessLedgerError::StateUnavailable => {
                                ProcessPreEffectFailure::GatewayUnavailable
                            }
                        })
                });
                outcome
                    .map(|_| ToolAdmissionDecision::Passed)
                    .or_else(|failure| self.reject(request, stage, failure))
            }
            GateStage::Containment => match self.probe.verify_containment() {
                Ok(()) => Ok(ToolAdmissionDecision::Passed),
                Err(_) => self.reject(request, stage, ProcessPreEffectFailure::Containment),
            },
            GateStage::EffectAdmission => self.admit(request),
        }
    }
}

impl ProcessAdmission {
    fn admit(
        &self,
        request: &ToolDispatchRequest,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| ToolAdmissionError::Unavailable)?;
        let call = pending
            .get_mut(&request.invocation_id)
            .ok_or(ToolAdmissionError::Unavailable)?;
        if call.admission_evidence().request_digest() != request.request_digest {
            return self.reject(
                request,
                GateStage::EffectAdmission,
                ProcessPreEffectFailure::CapabilityPreflight,
            );
        }
        let identity = call.identity();
        let evidence = call.admission_evidence();
        let permit_digest = evidence.permit_digest();
        let guard = self
            .ledger
            .begin_admission(identity.clone(), evidence)
            .map_err(|_| ToolAdmissionError::Unavailable)?;
        #[cfg(test)]
        if matches!(self.fault, Some(ProcessGateFault::PanicFinalValidation)) {
            panic!("deterministic final validation fault");
        }
        let validated = match self
            .authority
            .bind_call(call.material().intent().lifecycle_binding())
            .and_then(|boundary| {
                boundary.validate(
                    call.material().intent().clone(),
                    Some(call.material().capability()),
                    Some(call.material().approval()),
                    call.material().issued_at(),
                )
            }) {
            Ok(validated) => validated,
            Err(_) => {
                return self.reject(
                    request,
                    GateStage::EffectAdmission,
                    ProcessPreEffectFailure::Authorization,
                );
            }
        };
        #[cfg(test)]
        if matches!(self.fault, Some(ProcessGateFault::PanicWitnessAssignment)) {
            panic!("deterministic witness assignment fault");
        }
        let token = call.store_validated(validated, &identity);
        #[cfg(test)]
        if matches!(self.fault, Some(ProcessGateFault::PanicCommit)) {
            panic!("deterministic admission commit fault");
        }
        guard.commit(token);
        #[cfg(test)]
        self.effects.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        if matches!(self.fault, Some(ProcessGateFault::EffectUncertain)) {
            return Ok(ToolAdmissionDecision::Uncertain);
        }
        Ok(ToolAdmissionDecision::Winner(EffectAdmission {
            permit_id: super::super::process_call::process_permit_id(permit_digest),
        }))
    }
}

pub(super) fn take_failure(
    failures: &Failures,
    invocation: &str,
) -> Option<ProcessPreEffectFailure> {
    failures.lock().ok()?.remove(invocation)
}
