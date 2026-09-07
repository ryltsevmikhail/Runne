//! Idempotent cancellation journal (Plan Task 10 Step 3): the intent
//! is recorded once, late non-control frames are rejected after the
//! intent, and completion requires an authenticated terminal proof
//! with already-settled usage — otherwise the deadline escalation ends
//! the attempt as Uncertain. The durable journal itself is the store's
//! contract (product repo); this in-memory ledger defines the
//! transition rules the store migration must persist.

use crate::port::CancelDisposition;

/// Attempt lifecycle under cancellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelPhase {
    /// Intent recorded; frames of kind `text`/`tool` are now fenced.
    Intent,
    /// The single cancel signal was sent to the live generation.
    Signalled,
    /// Authenticated terminal stream item with settled usage arrived.
    TerminalSettled,
    /// Deadline exceeded without terminal proof: cleanup done,
    /// disposition is Uncertain — never a silent success.
    UncertainEscalated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationRecord {
    pub phase: CancelPhase,
    pub stream_id: [u8; 16],
    pub usage_settled: bool,
}

#[derive(Debug, Default)]
pub struct CancellationJournal {
    records: std::collections::BTreeMap<[u8; 16], CancellationRecord>,
}

impl CancellationJournal {
    /// Idempotent: duplicates keep the original record and return
    /// `AlreadyRequested`.
    pub fn record_intent(
        &mut self,
        attempt_id: [u8; 16],
        stream_id: [u8; 16],
    ) -> CancelDisposition {
        match self.records.get(&attempt_id) {
            Some(_) => CancelDisposition::AlreadyRequested,
            None => {
                self.records.insert(
                    attempt_id,
                    CancellationRecord {
                        phase: CancelPhase::Intent,
                        stream_id,
                        usage_settled: false,
                    },
                );
                CancelDisposition::Requested
            }
        }
    }

    /// Marks the one cancel signal delivered. Only valid after intent.
    pub fn record_signal(
        &mut self,
        attempt_id: [u8; 16],
    ) -> Result<(), crate::error::ProviderError> {
        let r = self
            .records
            .get_mut(&attempt_id)
            .ok_or(crate::error::ProviderError::FrameMismatch)?;
        if r.phase == CancelPhase::Intent {
            r.phase = CancelPhase::Signalled;
        }
        Ok(())
    }

    /// Accepts the authenticated terminal proof. Requires the cancel
    /// signal phase and settled usage; anything less escalates.
    pub fn record_terminal_proof(
        &mut self,
        attempt_id: [u8; 16],
        usage_settled: bool,
    ) -> Result<(), crate::error::ProviderError> {
        let r = self
            .records
            .get_mut(&attempt_id)
            .ok_or(crate::error::ProviderError::FrameMismatch)?;
        if r.phase != CancelPhase::Signalled {
            return Err(crate::error::ProviderError::MalformedStream);
        }
        if !usage_settled {
            r.phase = CancelPhase::UncertainEscalated;
            return Err(crate::error::ProviderError::MalformedStream);
        }
        r.usage_settled = true;
        r.phase = CancelPhase::TerminalSettled;
        Ok(())
    }

    /// Deadline escalation without terminal proof.
    pub fn escalate_uncertain(
        &mut self,
        attempt_id: [u8; 16],
    ) -> Result<(), crate::error::ProviderError> {
        let r = self
            .records
            .get_mut(&attempt_id)
            .ok_or(crate::error::ProviderError::FrameMismatch)?;
        if matches!(
            r.phase,
            CancelPhase::TerminalSettled | CancelPhase::UncertainEscalated
        ) {
            return Ok(());
        }
        r.phase = CancelPhase::UncertainEscalated;
        Ok(())
    }

    /// After the intent only terminal/control evidence may pass;
    /// late `text` frames are rejected by the caller.
    pub fn late_text_allowed(&self, attempt_id: [u8; 16]) -> bool {
        !self.records.contains_key(&attempt_id)
    }

    pub fn state(&self, attempt_id: &[u8; 16]) -> Option<&CancellationRecord> {
        self.records.get(attempt_id)
    }

    /// Attempts that ended Uncertain — the reconciliation input.
    pub fn uncertain(&self) -> Vec<[u8; 16]> {
        self.records
            .iter()
            .filter(|(_, r)| r.phase == CancelPhase::UncertainEscalated)
            .map(|(a, _)| *a)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_is_idempotent() {
        let mut j = CancellationJournal::default();
        assert_eq!(
            j.record_intent([1; 16], [2; 16]),
            CancelDisposition::Requested
        );
        assert_eq!(
            j.record_intent([1; 16], [2; 16]),
            CancelDisposition::AlreadyRequested
        );
    }

    #[test]
    fn terminal_proof_requires_signal_and_usage() {
        let mut j = CancellationJournal::default();
        assert!(j.record_terminal_proof([1; 16], true).is_err());
        j.record_intent([1; 16], [2; 16]);
        j.record_signal([1; 16]).expect("signal");
        assert!(j.record_terminal_proof([1; 16], false).is_err());
        assert_eq!(
            j.state(&[1; 16]).unwrap().phase,
            CancelPhase::UncertainEscalated
        );
        j.record_intent([3; 16], [4; 16]);
        j.record_signal([3; 16]).expect("signal");
        j.record_terminal_proof([3; 16], true).expect("proof");
        assert_eq!(
            j.state(&[3; 16]).unwrap().phase,
            CancelPhase::TerminalSettled
        );
    }

    #[test]
    fn late_text_is_fenced_after_intent() {
        let mut j = CancellationJournal::default();
        assert!(j.late_text_allowed([1; 16]));
        j.record_intent([1; 16], [2; 16]);
        assert!(!j.late_text_allowed([1; 16]));
    }

    #[test]
    fn escalation_lists_uncertain_attempts() {
        let mut j = CancellationJournal::default();
        j.record_intent([1; 16], [2; 16]);
        j.escalate_uncertain([1; 16]).expect("escalate");
        assert_eq!(j.uncertain(), vec![[1; 16]]);
    }
}
