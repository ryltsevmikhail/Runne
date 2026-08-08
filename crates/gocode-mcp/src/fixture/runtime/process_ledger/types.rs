use std::sync::MutexGuard;

use gocode_tools::ValidatedProcessIntentV1;

use crate::fixture::FixtureCallResult;

use super::super::super::process_call::{ProcessDispatchPayload, ProcessEffectKey};
use super::super::FixtureState;
use super::super::process_audit::FixtureAuditRecord;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::fixture) enum ProcessLedgerState {
    Reserved,
    Refunded,
    Admitted,
    Completed {
        attempt: u64,
        audit: Box<FixtureAuditRecord>,
    },
    Uncertain(ProcessUncertainReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fixture) enum ProcessRefundReason {
    Authorization,
    Containment,
    #[cfg(test)]
    Budget,
    GatewayUnavailable,
    CapabilityPreflight,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fixture) enum ProcessPreEffectFailure {
    Authorization,
    Containment,
    #[cfg(test)]
    Budget,
    GatewayUnavailable,
    CapabilityPreflight,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fixture) enum ProcessUncertainReason {
    Denied,
    Executor,
    Host,
    Lifecycle,
    Cleanup,
    Pending,
    Ledger,
    State,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessReceiptIdentity {
    pub(super) invocation_id: String,
    pub(super) key_digest: [u8; 32],
    pub(super) attempt: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessReservationReceipt {
    pub(super) identity: ProcessReceiptIdentity,
}
pub(in crate::fixture) struct ProcessLedgerEntry {
    pub(super) key: ProcessEffectKey,
    pub(super) current_attempt: u64,
    pub(super) refunded_through: u64,
    pub(super) state: ProcessLedgerState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessAdmissionEvidence {
    invocation_id: String,
    request_digest: [u8; 32],
    permit_digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessEffectEvidence {
    pub(super) invocation_id: String,
    pub(super) request_digest: [u8; 32],
    pub(super) binding_digest: [u8; 32],
    pub(super) issuer_digest: [u8; 32],
    pub(super) definition_digest: [u8; 32],
    pub(super) approval_digest: [u8; 32],
    pub(super) connection_digest: [u8; 32],
    pub(super) generation: u64,
    pub(super) tool_digest: [u8; 32],
    pub(super) intent_digest: [u8; 32],
    pub(in crate::fixture) capability_digest: [u8; 32],
    pub(in crate::fixture) permit_digest: [u8; 32],
}
#[derive(Debug, PartialEq, Eq)]
pub(in crate::fixture) struct ProcessConfirmedReceipt {
    pub(super) identity: ProcessReceiptIdentity,
    pub(super) result: FixtureCallResult,
}
pub(in crate::fixture) enum ProcessPhaseOutcome {
    PreEffectDenied {
        failure: ProcessPreEffectFailure,
        receipt: ProcessReservationReceipt,
        payload: Box<ProcessDispatchPayload>,
    },
    EffectCompleted {
        receipt: ProcessConfirmedReceipt,
    },
    EffectUncertain {
        receipt: ProcessConfirmedReceipt,
        reason: ProcessUncertainReason,
    },
    StateUnavailableAfterAdmission,
}
pub(in crate::fixture) struct PendingProcessCall {
    payload: ProcessDispatchPayload,
    identity: ProcessReceiptIdentity,
    admission_evidence: ProcessAdmissionEvidence,
    witness: Option<ProcessPendingWitness>,
}
pub(in crate::fixture) struct ProcessPendingWitness {
    validated: ValidatedProcessIntentV1,
    identity: ProcessReceiptIdentity,
    evidence: ProcessAdmissionEvidence,
}
pub(in crate::fixture) struct PendingWitnessToken {
    identity: ProcessReceiptIdentity,
    evidence: ProcessAdmissionEvidence,
}
pub(in crate::fixture) struct ProcessAdmissionGuard<'a> {
    pub(super) state: MutexGuard<'a, FixtureState>,
    pub(super) identity: ProcessReceiptIdentity,
    pub(super) evidence: ProcessAdmissionEvidence,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fixture) enum ProcessLedgerError {
    ReceiptNotReserved,
    StateUnavailable,
}

impl ProcessAdmissionEvidence {
    pub(in crate::fixture) fn new(
        invocation_id: String,
        request_digest: [u8; 32],
        permit_digest: [u8; 32],
    ) -> Self {
        Self {
            invocation_id,
            request_digest,
            permit_digest,
        }
    }
    pub(in crate::fixture) fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub(in crate::fixture) fn permit_digest(&self) -> [u8; 32] {
        self.permit_digest
    }
}
impl ProcessEffectEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::fixture) fn new(
        invocation_id: String,
        request_digest: [u8; 32],
        binding_digest: [u8; 32],
        issuer_digest: [u8; 32],
        definition_digest: [u8; 32],
        approval_digest: [u8; 32],
        connection_digest: [u8; 32],
        generation: u64,
        tool_digest: [u8; 32],
        intent_digest: [u8; 32],
        capability_digest: [u8; 32],
        permit_digest: [u8; 32],
    ) -> Self {
        Self {
            invocation_id,
            request_digest,
            binding_digest,
            issuer_digest,
            definition_digest,
            approval_digest,
            connection_digest,
            generation,
            tool_digest,
            intent_digest,
            capability_digest,
            permit_digest,
        }
    }
}
impl ProcessReservationReceipt {
    pub(super) fn new(identity: ProcessReceiptIdentity) -> Self {
        Self { identity }
    }
    pub(in crate::fixture) fn identity(&self) -> ProcessReceiptIdentity {
        self.identity.clone()
    }
    #[cfg(test)]
    pub(in crate::fixture) fn duplicate_for_test(&self) -> Self {
        Self::new(self.identity())
    }
}
impl ProcessReceiptIdentity {
    pub(in crate::fixture) fn invocation_id(&self) -> &str {
        &self.invocation_id
    }
    pub(in crate::fixture) fn key_digest(&self) -> [u8; 32] {
        self.key_digest
    }
}
impl ProcessConfirmedReceipt {
    pub(in crate::fixture) fn result(&self) -> FixtureCallResult {
        self.result
    }
}
impl PendingProcessCall {
    pub(in crate::fixture) fn new(
        payload: ProcessDispatchPayload,
        identity: ProcessReceiptIdentity,
        admission_evidence: ProcessAdmissionEvidence,
    ) -> Self {
        Self {
            payload,
            identity,
            admission_evidence,
            witness: None,
        }
    }
    pub(in crate::fixture) fn store_validated(
        &mut self,
        validated: ValidatedProcessIntentV1,
        identity: &ProcessReceiptIdentity,
    ) -> PendingWitnessToken {
        assert_eq!(
            identity, &self.identity,
            "pending witness identity mismatch"
        );
        let evidence = self.admission_evidence.clone();
        self.witness = Some(ProcessPendingWitness {
            validated,
            identity: self.identity.clone(),
            evidence: evidence.clone(),
        });
        PendingWitnessToken {
            identity: self.identity.clone(),
            evidence,
        }
    }
    pub(in crate::fixture) fn material(
        &self,
    ) -> &super::super::super::process_call::ProcessCallMaterial {
        self.payload.material()
    }
    pub(in crate::fixture) fn mcp(&self) -> &crate::McpToolDispatchCapability {
        self.payload.mcp()
    }
    pub(in crate::fixture) fn identity(&self) -> ProcessReceiptIdentity {
        self.identity.clone()
    }
    pub(in crate::fixture) fn admission_evidence(&self) -> ProcessAdmissionEvidence {
        self.admission_evidence.clone()
    }
    pub(in crate::fixture) fn take_validated(
        &mut self,
        identity: &ProcessReceiptIdentity,
        evidence: &ProcessAdmissionEvidence,
    ) -> Option<ValidatedProcessIntentV1> {
        let witness = self.witness.take()?;
        (witness.identity == *identity && witness.evidence == *evidence)
            .then_some(witness.validated)
    }
    pub(in crate::fixture) fn into_payload(self) -> ProcessDispatchPayload {
        self.payload
    }
}
impl PendingWitnessToken {
    pub(in crate::fixture) fn consume(self) -> (ProcessReceiptIdentity, ProcessAdmissionEvidence) {
        (self.identity, self.evidence)
    }
}
#[cfg(test)]
impl ProcessReceiptIdentity {
    pub(in crate::fixture) fn attempt_for_test(&self) -> u64 {
        self.attempt
    }
}
