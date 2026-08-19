use crate::fixture::FixtureCallResult;

use super::super::process_audit::{FixtureAuditProcessPhase, FixtureAuditRecord};
use super::reservation::receipt_matches;
use super::{
    FixtureProcessLedgerPort, PendingProcessCall, ProcessConfirmedReceipt, ProcessEffectEvidence,
    ProcessLedgerState, ProcessPhaseOutcome, ProcessReservationReceipt, ProcessUncertainReason,
};

impl FixtureProcessLedgerPort {
    pub(in crate::fixture) fn settle_completed(
        &self,
        receipt: ProcessReservationReceipt,
        pending: PendingProcessCall,
    ) -> ProcessPhaseOutcome {
        settle_completed(&self.state, receipt, pending)
    }
    pub(in crate::fixture) fn settle_uncertain(
        &self,
        receipt: ProcessReservationReceipt,
        reason: ProcessUncertainReason,
    ) -> ProcessPhaseOutcome {
        settle_uncertain(&self.state, receipt, reason)
    }
}
fn settle_completed(
    state: &std::sync::Arc<std::sync::Mutex<super::super::FixtureState>>,
    receipt: ProcessReservationReceipt,
    pending: PendingProcessCall,
) -> ProcessPhaseOutcome {
    let mut state = match state.lock() {
        Ok(state) => state,
        Err(_) => return ProcessPhaseOutcome::StateUnavailableAfterAdmission,
    };
    let Some(entry) = state.process_ledger.get(&receipt.identity.invocation_id) else {
        return ProcessPhaseOutcome::StateUnavailableAfterAdmission;
    };
    if !receipt_matches(entry, &receipt.identity) {
        return ProcessPhaseOutcome::StateUnavailableAfterAdmission;
    }
    if let Some(outcome) = terminal_replay(entry, &receipt) {
        return outcome;
    }
    if !matches!(entry.state, ProcessLedgerState::Admitted) {
        return ProcessPhaseOutcome::StateUnavailableAfterAdmission;
    }
    let key = entry.key.clone();
    let attempt = entry.current_attempt;
    let evidence = match effect_evidence(&receipt, &pending, &key) {
        Some(evidence) => evidence,
        None => {
            return settle_uncertain_locked(&mut state, receipt, ProcessUncertainReason::Ledger);
        }
    };
    if !effect_matches(&key, &evidence) {
        return settle_uncertain_locked(&mut state, receipt, ProcessUncertainReason::Ledger);
    }
    let audit = FixtureAuditRecord::process(
        &key,
        FixtureAuditProcessPhase::Completed,
        None,
        Some(FixtureCallResult::Completed),
        Some(&evidence),
    );
    state
        .process_ledger
        .get_mut(&receipt.identity.invocation_id)
        .expect("checked entry")
        .state = ProcessLedgerState::Completed {
        attempt,
        audit: Box::new(audit.clone()),
    };
    state.audit.push(audit);
    ProcessPhaseOutcome::EffectCompleted {
        receipt: ProcessConfirmedReceipt {
            identity: receipt.identity,
            result: FixtureCallResult::Completed,
        },
    }
}

fn effect_evidence(
    receipt: &ProcessReservationReceipt,
    pending: &PendingProcessCall,
    key: &super::super::super::process_call::ProcessEffectKey,
) -> Option<ProcessEffectEvidence> {
    let (binding, request) = pending.mcp().verified_process_call();
    let fields = key.audit_fields();
    let admission = pending.admission_evidence();
    let intent_digest = *pending.material().intent().digest().as_bytes();
    let capability_id = pending.material().capability().id_label();
    (request.invocation_id == receipt.identity.invocation_id
        && request.request_digest == fields.request_digest()
        && binding.binding_digest() == fields.binding_digest()
        && binding.connection_id() == key.connection_id()
        && binding.generation() == fields.generation()
        && admission.request_digest() == request.request_digest
        && admission.permit_digest()
            == super::super::super::process_call::process_permit_digest(
                receipt.identity.key_digest(),
                &capability_id,
                intent_digest,
            ))
    .then(|| {
        ProcessEffectEvidence::new(
            request.invocation_id,
            request.request_digest,
            fields.binding_digest(),
            fields.issuer_digest(),
            fields.definition_digest(),
            fields.approval_digest(),
            super::super::super::process_call::audit_connection_digest(binding.connection_id()),
            fields.generation(),
            fields.tool_digest(),
            intent_digest,
            super::super::super::process_call::audit_capability_digest(&capability_id),
            admission.permit_digest(),
        )
    })
}
fn settle_uncertain(
    state: &std::sync::Arc<std::sync::Mutex<super::super::FixtureState>>,
    receipt: ProcessReservationReceipt,
    reason: ProcessUncertainReason,
) -> ProcessPhaseOutcome {
    let mut state = match state.lock() {
        Ok(state) => state,
        Err(_) => return ProcessPhaseOutcome::StateUnavailableAfterAdmission,
    };
    let Some(entry) = state.process_ledger.get(&receipt.identity.invocation_id) else {
        return ProcessPhaseOutcome::StateUnavailableAfterAdmission;
    };
    if !receipt_matches(entry, &receipt.identity) {
        return ProcessPhaseOutcome::StateUnavailableAfterAdmission;
    }
    if let Some(outcome) = terminal_replay(entry, &receipt) {
        return outcome;
    }
    if !matches!(entry.state, ProcessLedgerState::Admitted) {
        return ProcessPhaseOutcome::StateUnavailableAfterAdmission;
    }
    settle_uncertain_locked(&mut state, receipt, reason)
}
fn settle_uncertain_locked(
    state: &mut super::super::FixtureState,
    receipt: ProcessReservationReceipt,
    reason: ProcessUncertainReason,
) -> ProcessPhaseOutcome {
    let key = state
        .process_ledger
        .get(&receipt.identity.invocation_id)
        .expect("checked entry")
        .key
        .clone();
    state
        .process_ledger
        .get_mut(&receipt.identity.invocation_id)
        .expect("checked entry")
        .state = ProcessLedgerState::Uncertain(reason);
    state.audit.push(FixtureAuditRecord::process(
        &key,
        FixtureAuditProcessPhase::Uncertain,
        Some(FixtureAuditRecord::uncertain_reason(reason)),
        Some(FixtureCallResult::Uncertain),
        None,
    ));
    ProcessPhaseOutcome::EffectUncertain {
        receipt: ProcessConfirmedReceipt {
            identity: receipt.identity,
            result: FixtureCallResult::Uncertain,
        },
        reason,
    }
}
fn terminal_replay(
    entry: &super::ProcessLedgerEntry,
    receipt: &ProcessReservationReceipt,
) -> Option<ProcessPhaseOutcome> {
    match &entry.state {
        ProcessLedgerState::Completed { audit, .. } => Some(ProcessPhaseOutcome::EffectCompleted {
            receipt: ProcessConfirmedReceipt {
                identity: receipt.identity(),
                result: audit.result().expect("completed result"),
            },
        }),
        ProcessLedgerState::Uncertain(reason) => Some(ProcessPhaseOutcome::EffectUncertain {
            receipt: ProcessConfirmedReceipt {
                identity: receipt.identity(),
                result: FixtureCallResult::Uncertain,
            },
            reason: *reason,
        }),
        _ => None,
    }
}
fn effect_matches(
    key: &super::super::super::process_call::ProcessEffectKey,
    evidence: &ProcessEffectEvidence,
) -> bool {
    let fields = key.audit_fields();
    evidence.invocation_id == key.invocation_id()
        && evidence.request_digest == fields.request_digest()
        && evidence.binding_digest == fields.binding_digest()
        && evidence.issuer_digest == fields.issuer_digest()
        && evidence.definition_digest == fields.definition_digest()
        && evidence.approval_digest == fields.approval_digest()
        && evidence.connection_digest
            == super::super::super::process_call::audit_connection_digest(key.connection_id())
        && evidence.generation == fields.generation()
        && evidence.tool_digest == fields.tool_digest()
        && evidence.intent_digest == fields.intent_digest()
}
