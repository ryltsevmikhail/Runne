//! Byte-identical usage settlement (Plan Task 12): the exact terminal
//! prompt/output/reasoning tokens, active time and measured peak are
//! persisted ONCE. A second settlement with byte-identical evidence is
//! `AlreadySettled`; conflicting evidence freezes the attempt (no
//! partial or averaged settlements exist).

use std::collections::BTreeMap;

/// Exact terminal usage evidence. Byte-identity is over the tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageEvidence {
    pub prompt_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub active_time_ms: u64,
    pub peak_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementDisposition {
    Settled,
    AlreadySettled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementError {
    /// Conflicting evidence for an already-settled attempt: the attempt
    /// is frozen for the composition layer.
    ConflictFrozen,
}

#[derive(Debug, Default)]
pub struct SettlementLedger {
    settled: BTreeMap<[u8; 16], UsageEvidence>,
    frozen: std::collections::BTreeSet<[u8; 16]>,
}

impl SettlementLedger {
    /// Settles the attempt exactly once per byte-identical evidence.
    pub fn settle(
        &mut self,
        attempt_id: [u8; 16],
        evidence: UsageEvidence,
    ) -> Result<SettlementDisposition, SettlementError> {
        match self.settled.get(&attempt_id) {
            None => {
                self.settled.insert(attempt_id, evidence);
                Ok(SettlementDisposition::Settled)
            }
            Some(existing) => {
                if *existing == evidence {
                    Ok(SettlementDisposition::AlreadySettled)
                } else {
                    self.frozen.insert(attempt_id);
                    Err(SettlementError::ConflictFrozen)
                }
            }
        }
    }

    pub fn evidence_of(&self, attempt_id: &[u8; 16]) -> Option<UsageEvidence> {
        self.settled.get(attempt_id).copied()
    }

    pub fn is_frozen(&self, attempt_id: &[u8; 16]) -> bool {
        self.frozen.contains(attempt_id)
    }
}
