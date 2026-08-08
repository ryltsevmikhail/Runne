use std::sync::{Arc, Mutex};

use crate::fixture::FixtureMcpFailure;

use super::super::FixtureMcpRuntime;
use super::super::process_audit::{FixtureAuditProcessPhase, FixtureAuditRecord};
use super::reservation::receipt_matches;
use super::{
    ProcessAdmissionEvidence, ProcessAdmissionGuard, ProcessLedgerError, ProcessLedgerState,
    ProcessReceiptIdentity,
};

#[derive(Clone)]
pub(in crate::fixture) struct FixtureProcessLedgerPort {
    pub(super) state: Arc<Mutex<super::super::FixtureState>>,
}

impl FixtureMcpRuntime {
    pub(in crate::fixture) fn process_ledger_port(&self) -> FixtureProcessLedgerPort {
        FixtureProcessLedgerPort {
            state: Arc::clone(&self.state),
        }
    }
}
impl FixtureProcessLedgerPort {
    pub(in crate::fixture) fn verify_reserved(
        &self,
        identity: &ProcessReceiptIdentity,
    ) -> Result<(), ProcessLedgerError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ProcessLedgerError::StateUnavailable)?;
        match state.process_ledger.get(&identity.invocation_id) {
            Some(entry)
                if receipt_matches(entry, identity)
                    && matches!(entry.state, ProcessLedgerState::Reserved) =>
            {
                Ok(())
            }
            _ => Err(ProcessLedgerError::ReceiptNotReserved),
        }
    }
    pub(in crate::fixture) fn begin_admission(
        &self,
        identity: ProcessReceiptIdentity,
        evidence: ProcessAdmissionEvidence,
    ) -> Result<ProcessAdmissionGuard<'_>, FixtureMcpFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| FixtureMcpFailure::InvalidStateTransition)?;
        if !matches!(state.process_ledger.get(&identity.invocation_id), Some(entry) if receipt_matches(entry, &identity) && matches!(entry.state, ProcessLedgerState::Reserved))
        {
            return Err(FixtureMcpFailure::InvalidStateTransition);
        }
        Ok(ProcessAdmissionGuard {
            state,
            identity,
            evidence,
        })
    }
}
impl ProcessAdmissionGuard<'_> {
    pub(in crate::fixture) fn commit(mut self, token: super::PendingWitnessToken) {
        let (identity, evidence) = token.consume();
        assert_eq!(identity, self.identity, "admission token identity mismatch");
        assert_eq!(evidence, self.evidence, "admission token evidence mismatch");
        let entry = self
            .state
            .process_ledger
            .get_mut(&self.identity.invocation_id)
            .expect("reserved process entry");
        assert!(
            matches!(entry.state, ProcessLedgerState::Reserved)
                && receipt_matches(entry, &self.identity),
            "admission receipt is not reserved"
        );
        let key = entry.key.clone();
        entry.state = ProcessLedgerState::Admitted;
        self.state.audit.push(FixtureAuditRecord::process(
            &key,
            FixtureAuditProcessPhase::Admitted,
            None,
            None,
            None,
        ));
    }
}
