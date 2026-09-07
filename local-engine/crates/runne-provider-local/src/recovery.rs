//! Restart reconciliation (Plan Task 10 Step 4): a new host generation
//! never inherits a live stream or artifact grant and may serve a new
//! attempt only after every previous uncertain cleanup has recorded
//! its evidence. There is deliberately NO redispatch API: transport
//! loss can never be converted into an automatic re-send by the
//! coordinator.

use crate::cancellation::CancelPhase;

/// Digest-shaped cleanup evidence (bounded, opaque here; the product
/// composition binds it to process-tree evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupEvidence(pub [u8; 32]);

#[derive(Debug, Default)]
pub struct RecoveryLedger {
    uncertain: std::collections::BTreeSet<[u8; 16]>,
    resolved: std::collections::BTreeMap<[u8; 16], CleanupEvidence>,
}

impl RecoveryLedger {
    /// Registers an attempt whose disposition is Uncertain.
    pub fn mark_uncertain(&mut self, attempt_id: [u8; 16]) {
        if !self.resolved.contains_key(&attempt_id) {
            self.uncertain.insert(attempt_id);
        }
    }

    /// Resolves one uncertain attempt with recorded evidence. Returns
    /// false if the attempt was not uncertain (idempotent no-op).
    pub fn record_cleanup_evidence(
        &mut self,
        attempt_id: [u8; 16],
        evidence: CleanupEvidence,
    ) -> bool {
        if self.uncertain.remove(&attempt_id) {
            self.resolved.insert(attempt_id, evidence);
            true
        } else {
            false
        }
    }

    /// A fresh generation admits new work only with zero unresolved
    /// uncertain cleanups.
    pub fn can_admit_new_generation(&self) -> bool {
        self.uncertain.is_empty()
    }

    pub fn unresolved(&self) -> Vec<[u8; 16]> {
        self.uncertain.iter().copied().collect()
    }

    /// Feeds the cancellation journal's escalated attempts in.
    pub fn absorb_cancel_phases(&mut self, phases: &[([u8; 16], CancelPhase)]) {
        for (attempt, phase) in phases {
            if *phase == CancelPhase::UncertainEscalated {
                self.mark_uncertain(*attempt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_blocks_new_generation_until_evidence() {
        let mut l = RecoveryLedger::default();
        l.mark_uncertain([1; 16]);
        assert!(!l.can_admit_new_generation());
        // Wrong-attempt evidence does not unblock.
        assert!(!l.record_cleanup_evidence([9; 16], CleanupEvidence([7; 32])));
        assert!(!l.can_admit_new_generation());
        assert!(l.record_cleanup_evidence([1; 16], CleanupEvidence([7; 32])));
        assert!(l.can_admit_new_generation());
    }

    #[test]
    fn resolved_attempts_stay_resolved() {
        let mut l = RecoveryLedger::default();
        l.mark_uncertain([1; 16]);
        assert!(l.record_cleanup_evidence([1; 16], CleanupEvidence([7; 32])));
        l.mark_uncertain([1; 16]);
        assert!(l.can_admit_new_generation(), "resolved never re-uncertain");
    }

    #[test]
    fn cancellation_escalations_flow_into_recovery() {
        let mut l = RecoveryLedger::default();
        l.absorb_cancel_phases(&[([1; 16], CancelPhase::UncertainEscalated)]);
        assert!(!l.can_admit_new_generation());
        l.absorb_cancel_phases(&[([2; 16], CancelPhase::TerminalSettled)]);
        assert_eq!(l.unresolved(), vec![[1; 16]]);
    }
}
