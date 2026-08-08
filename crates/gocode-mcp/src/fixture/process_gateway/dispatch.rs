use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use super::super::{
    process_call::{ClaimedProcessCall, ProcessDispatchPayload},
    runtime::process_ledger::{
        PendingProcessCall, ProcessAdmissionEvidence, ProcessPhaseOutcome, ProcessPreEffectFailure,
        ProcessReservationReceipt, ProcessUncertainReason,
    },
};
use super::McpProcessToolGateway;
use gocode_tools::{
    EffectAdmission, ProcessContractHostV1, ProcessHostOutcomeV1, ProcessToolExecutorPort,
    ToolDispatchRequest, ToolExecutionHandle, ToolExecutorError, ToolExecutorPort,
    ToolGatewayError,
};

pub(super) type PendingCalls = Arc<Mutex<BTreeMap<String, PendingProcessCall>>>;
pub(super) type HostOutcomes = Arc<Mutex<BTreeMap<String, ProcessHostOutcomeV1>>>;

pub(in crate::fixture) struct McpProcessExecutor {
    pub(super) pending: PendingCalls,
    pub(super) host: Arc<Mutex<ProcessContractHostV1>>,
    pub(super) outcomes: HostOutcomes,
    #[cfg(test)]
    pub(super) host_dispatches: Arc<std::sync::atomic::AtomicUsize>,
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
            let identity = call.identity();
            let evidence = call.admission_evidence();
            (evidence.request_digest() == request.request_digest
                && admission.permit_id
                    == super::super::process_call::process_permit_id(evidence.permit_digest()))
            .then(|| call.take_validated(&identity, &evidence))
            .flatten()
            .ok_or(ToolExecutorError::Rejected)?
        };
        let handle = ToolExecutionHandle {
            execution_id: admission.permit_id.clone(),
        };
        #[cfg(test)]
        self.host_dispatches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

pub(super) fn dispatch_claimed(
    gateway: &McpProcessToolGateway,
    claimed: ClaimedProcessCall<'_>,
    receipt: ProcessReservationReceipt,
    payload: ProcessDispatchPayload,
) -> ProcessPhaseOutcome {
    let request = claimed.request().clone();
    let identity = receipt.identity();
    let permit_digest = super::super::process_call::process_permit_digest(
        identity.key_digest(),
        &payload.material().capability().id_label(),
        *payload.material().intent().digest().as_bytes(),
    );
    let evidence = ProcessAdmissionEvidence::new(
        request.invocation_id.clone(),
        request.request_digest,
        permit_digest,
    );
    let mut pending = match gateway.pending.lock() {
        Ok(pending) => pending,
        Err(_) => {
            return ProcessPhaseOutcome::PreEffectDenied {
                failure: ProcessPreEffectFailure::GatewayUnavailable,
                receipt,
                payload: Box::new(payload),
            };
        }
    };
    if pending.contains_key(&request.invocation_id) {
        return ProcessPhaseOutcome::PreEffectDenied {
            failure: ProcessPreEffectFailure::GatewayUnavailable,
            receipt,
            payload: Box::new(payload),
        };
    }
    pending.insert(
        request.invocation_id.clone(),
        PendingProcessCall::new(payload, identity, evidence),
    );
    drop(pending);
    let result = gateway.gateway.dispatch(request.clone());
    #[cfg(test)]
    if let Some(super::ProcessGateFault::Uncertain(reason)) = gateway.fault {
        let outcome = settle_uncertain(gateway, receipt, reason);
        gateway.wait_after_settlement_for_test();
        claimed.finish_after_settlement();
        return outcome;
    }
    let outcome = match result {
        Ok(handle) => super::terminal::settle_host_outcome(gateway, &request, handle, receipt),
        Err(ToolGatewayError::Admission(error)) => {
            let failure = super::admission::take_failure(&gateway.failures, &request.invocation_id)
                .unwrap_or(ProcessPreEffectFailure::GatewayUnavailable);
            if matches!(error, gocode_tools::ToolAdmissionError::Rejected(_)) {
                pre_effect(gateway, &request.invocation_id, receipt, failure)
            } else {
                pre_effect(
                    gateway,
                    &request.invocation_id,
                    receipt,
                    ProcessPreEffectFailure::GatewayUnavailable,
                )
            }
        }
        Err(error) => settle_uncertain(gateway, receipt, post_admission_reason(&error)),
    };
    #[cfg(test)]
    gateway.wait_after_settlement_for_test();
    claimed.finish_after_settlement();
    outcome
}

fn post_admission_reason(error: &ToolGatewayError) -> ProcessUncertainReason {
    match error {
        ToolGatewayError::Executor(_) => ProcessUncertainReason::Executor,
        ToolGatewayError::UncertainAfterAdmission => ProcessUncertainReason::State,
        _ => ProcessUncertainReason::State,
    }
}

fn pre_effect(
    gateway: &McpProcessToolGateway,
    invocation: &str,
    receipt: ProcessReservationReceipt,
    failure: ProcessPreEffectFailure,
) -> ProcessPhaseOutcome {
    let payload = gateway
        .pending
        .lock()
        .ok()
        .and_then(|mut pending| pending.remove(invocation))
        .map(PendingProcessCall::into_payload);
    match payload {
        Some(payload) => ProcessPhaseOutcome::PreEffectDenied {
            failure,
            receipt,
            payload: Box::new(payload),
        },
        None => settle_uncertain(gateway, receipt, ProcessUncertainReason::Pending),
    }
}

pub(super) fn settle_uncertain(
    gateway: &McpProcessToolGateway,
    receipt: ProcessReservationReceipt,
    reason: ProcessUncertainReason,
) -> ProcessPhaseOutcome {
    let _ = gateway
        .pending
        .lock()
        .map(|mut pending| pending.remove(receipt.identity().invocation_id()));
    gateway.ledger.settle_uncertain(receipt, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_admission_errors_keep_executor_and_state_causes_distinct() {
        assert_eq!(
            post_admission_reason(&ToolGatewayError::Executor(ToolExecutorError::Unavailable)),
            ProcessUncertainReason::Executor
        );
        assert_eq!(
            post_admission_reason(&ToolGatewayError::UncertainAfterAdmission),
            ProcessUncertainReason::State
        );
    }
}
