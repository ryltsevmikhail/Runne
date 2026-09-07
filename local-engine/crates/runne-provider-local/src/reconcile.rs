//! Reconciliation: evidence-driven Absent/Settled/Uncertain. Reusing an
//! attempt with different prepared bytes is AttemptConflict.

use crate::error::ProviderError;
use crate::port::Reconciliation;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Known-good digest of the settled render.
    Settled { render_digest: String },
    /// Dispatch started but terminal evidence never arrived.
    Uncertain,
}

#[derive(Default)]
pub struct ReconcileLedger {
    /// attempt_id → render digest observed at dispatch.
    digests: BTreeMap<[u8; 16], String>,
    /// attempt_id → outcome.
    outcomes: BTreeMap<[u8; 16], AttemptOutcome>,
}

impl ReconcileLedger {
    pub fn record_digest(&mut self, attempt_id: [u8; 16], render_digest: String) {
        self.digests.insert(attempt_id, render_digest);
    }

    pub fn record_outcome(&mut self, attempt_id: [u8; 16], outcome: AttemptOutcome) {
        self.outcomes.insert(attempt_id, outcome);
    }

    /// AttemptConflict when the presented render digest differs from the
    /// recorded one for the same attempt.
    pub fn check_binding(
        &self,
        attempt_id: &[u8; 16],
        render_digest: &str,
    ) -> Result<(), ProviderError> {
        if self
            .digests
            .get(attempt_id)
            .is_some_and(|recorded| recorded != render_digest)
        {
            return Err(ProviderError::AttemptConflict);
        }
        Ok(())
    }

    /// Reconcile per evidence; ambiguity never becomes success.
    pub fn reconcile(&self, attempt_id: &[u8; 16]) -> Result<Reconciliation, ProviderError> {
        match self.outcomes.get(attempt_id) {
            Some(AttemptOutcome::Settled { .. }) => Ok(Reconciliation::Settled),
            Some(AttemptOutcome::Uncertain) => Ok(Reconciliation::Uncertain),
            None => Ok(Reconciliation::Absent),
        }
    }
}
