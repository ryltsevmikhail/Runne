use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use gocode_tools::{
    EffectAdmission, GateStage, ProcessAuthorizationAuthorityV1, SandboxQualificationProbe,
    ToolAdmissionDecision, ToolAdmissionError, ToolAdmissionPort, ToolDispatchRequest,
};

use super::{GateFailure, PendingCalls};

pub(super) struct ProcessAdmission {
    pub(super) authority: ProcessAuthorizationAuthorityV1,
    pub(super) probe: Arc<dyn SandboxQualificationProbe>,
    pub(super) pending: PendingCalls,
    pub(super) failures: Arc<Mutex<BTreeMap<String, GateFailure>>>,
    pub(super) effects: Arc<AtomicUsize>,
}

impl ProcessAdmission {
    fn reject(
        &self,
        invocation: &str,
        stage: GateStage,
        failure: GateFailure,
    ) -> Result<ToolAdmissionDecision, ToolAdmissionError> {
        self.failures
            .lock()
            .map_err(|_| ToolAdmissionError::Unavailable)?
            .insert(invocation.to_owned(), failure);
        Err(ToolAdmissionError::Rejected(stage))
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
                let result = {
                    let pending = self
                        .pending
                        .lock()
                        .map_err(|_| ToolAdmissionError::Unavailable)?;
                    let call = pending
                        .get(&request.invocation_id)
                        .ok_or(ToolAdmissionError::Unavailable)?;
                    if call.digest != request.request_digest || call.validated.is_some() {
                        Err(GateFailure::InvalidBinding)
                    } else {
                        self.authority
                            .bind_call(call.lifecycle.clone())
                            .and_then(|boundary| {
                                boundary.preflight_authorization(
                                    &call.intent,
                                    call.capability.as_ref(),
                                    call.approval.as_ref(),
                                    call.now,
                                )
                            })
                            .map_err(GateFailure::Authorization)
                    }
                };
                match result {
                    Ok(()) => Ok(ToolAdmissionDecision::Passed),
                    Err(failure) => {
                        self.reject(&request.invocation_id, GateStage::Capability, failure)
                    }
                }
            }
            GateStage::Approval | GateStage::Budget => Ok(ToolAdmissionDecision::Passed),
            GateStage::Containment => match self.probe.qualify() {
                Ok(()) => Ok(ToolAdmissionDecision::Passed),
                Err(disposition) => self.reject(
                    &request.invocation_id,
                    GateStage::Containment,
                    GateFailure::Sandbox(disposition),
                ),
            },
            GateStage::EffectAdmission => {
                let permit = EffectAdmission {
                    permit_id: format!(
                        "mcp-process:{}:{:02x}",
                        request.invocation_id, request.request_digest[0]
                    ),
                };
                let result = {
                    let mut pending = self
                        .pending
                        .lock()
                        .map_err(|_| ToolAdmissionError::Unavailable)?;
                    let call = pending
                        .get_mut(&request.invocation_id)
                        .ok_or(ToolAdmissionError::Unavailable)?;
                    if call.digest != request.request_digest || call.validated.is_some() {
                        Err(GateFailure::InvalidBinding)
                    } else {
                        let intent = call.intent.clone();
                        self.authority
                            .bind_call(call.lifecycle.clone())
                            .and_then(|boundary| {
                                boundary.validate(
                                    intent,
                                    call.capability.as_ref(),
                                    call.approval.as_ref(),
                                    call.now,
                                )
                            })
                            .map(|validated| call.validated = Some(validated))
                            .map_err(GateFailure::Authorization)
                    }
                };
                match result {
                    Ok(()) => {
                        self.effects.fetch_add(1, Ordering::Relaxed);
                        Ok(ToolAdmissionDecision::Winner(permit))
                    }
                    Err(failure) => {
                        self.reject(&request.invocation_id, GateStage::EffectAdmission, failure)
                    }
                }
            }
        }
    }
}
