use crate::EffectAdmission;
use gocode_platform_ports::process::{MonotonicDeadline, ProcessLifecycleBindingV1};

use super::{ProcessContractErrorV1, ProcessLifecycleStateV1, ProcessTerminalSettlementV1};

/// Read-only stable journal key for one outer admission projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProcessClaimKeyV1 {
    permit_id: String,
}

impl ProcessClaimKeyV1 {
    pub(crate) fn new(permit_id: String) -> Self {
        Self { permit_id }
    }

    /// Returns the exact pre-issued outer permit identifier.
    #[must_use]
    pub(crate) fn permit_id(&self) -> &str {
        &self.permit_id
    }
}

/// Exact marker-safe identity tuple bound to one process claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessClaimBindingV1 {
    owner_id: [u8; 16],
    attempt_id: [u8; 16],
    session_id: [u8; 16],
    generation: [u8; 16],
    tree_id: [u8; 16],
}

impl ProcessClaimBindingV1 {
    /// Constructs a non-sentinel exact identity binding.
    #[cfg(test)]
    pub(crate) fn new(
        owner_id: [u8; 16],
        attempt_id: [u8; 16],
        session_id: [u8; 16],
        generation: [u8; 16],
        tree_id: [u8; 16],
    ) -> Result<Self, ProcessContractErrorV1> {
        if [owner_id, attempt_id, session_id, generation, tree_id]
            .iter()
            .any(|identity| identity.iter().all(|byte| *byte == 0))
        {
            return Err(ProcessContractErrorV1::GenerationMismatch);
        }
        Ok(Self {
            owner_id,
            attempt_id,
            session_id,
            generation,
            tree_id,
        })
    }

    /// Projects opaque lifecycle identities without creating dispatch authority.
    #[must_use]
    pub(crate) fn from_lifecycle(binding: &ProcessLifecycleBindingV1) -> Self {
        Self {
            owner_id: *binding.owner().as_bytes(),
            attempt_id: *binding.attempt().as_bytes(),
            session_id: *binding.session().as_bytes(),
            generation: *binding.generation().as_bytes(),
            tree_id: *binding.tree_handle().as_bytes(),
        }
    }
}

/// Fixture/conformance metadata for projecting an already-issued outer admission.
///
/// This low-level constructor is subordinate metadata, not dispatch authority;
/// production dispatch derives it only from a sealed validated witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessClaimInputV1 {
    key: ProcessClaimKeyV1,
    intent_digest: [u8; 32],
    binding: ProcessClaimBindingV1,
    deadline: MonotonicDeadline,
}

impl ProcessClaimInputV1 {
    /// Binds an existing nonempty admission to its exact intent and identities.
    pub(crate) fn new(
        admission: &EffectAdmission,
        intent_digest: [u8; 32],
        binding: ProcessClaimBindingV1,
        deadline: MonotonicDeadline,
    ) -> Result<Self, ProcessContractErrorV1> {
        if admission.permit_id.is_empty() {
            return Err(ProcessContractErrorV1::AdmissionMissing);
        }
        Ok(Self {
            key: ProcessClaimKeyV1::new(admission.permit_id.clone()),
            intent_digest,
            binding,
            deadline,
        })
    }

    /// Returns the exact outer permit identifier without creating authority.
    pub fn key(&self) -> &ProcessClaimKeyV1 {
        &self.key
    }

    pub(crate) const fn binding(&self) -> &ProcessClaimBindingV1 {
        &self.binding
    }

    pub(crate) const fn deadline(&self) -> MonotonicDeadline {
        self.deadline
    }

    pub(super) const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }
}

/// Replay-safe claim projection record containing only safe identity metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessClaimRecordV1 {
    input: ProcessClaimInputV1,
    state: ProcessLifecycleStateV1,
    settlement: Option<ProcessTerminalSettlementV1>,
    revision: u64,
    settlement_sequence: u64,
}

impl ProcessClaimRecordV1 {
    /// Creates the projection immediately after the outer admission is claimed.
    pub(crate) fn claimed(input: &ProcessClaimInputV1) -> Self {
        Self {
            input: input.clone(),
            state: ProcessLifecycleStateV1::Claimed,
            settlement: None,
            revision: 1,
            settlement_sequence: 0,
        }
    }

    /// Returns whether this record is the exact projection of `input`.
    pub(crate) fn matches(&self, input: &ProcessClaimInputV1) -> bool {
        self.input == *input
    }

    /// Returns the current closed lifecycle state.
    pub(crate) const fn state(&self) -> ProcessLifecycleStateV1 {
        self.state
    }

    pub(crate) const fn deadline(&self) -> MonotonicDeadline {
        self.input.deadline()
    }

    pub(super) const fn input(&self) -> &ProcessClaimInputV1 {
        &self.input
    }

    pub(super) const fn binding(&self) -> &ProcessClaimBindingV1 {
        self.input.binding()
    }

    /// Returns the CAS-derived revision of this claim record.
    #[must_use]
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the CAS-derived count of terminal settlements for this claim record.
    #[must_use]
    pub(crate) const fn settlement_sequence(&self) -> u64 {
        self.settlement_sequence
    }

    #[cfg(test)]
    pub(super) fn set_test_metadata(&mut self, revision: u64, settlement_sequence: u64) {
        self.revision = revision;
        self.settlement_sequence = settlement_sequence;
    }

    /// Applies one legal lifecycle transition without mutating on rejection.
    pub(crate) fn transition(
        &mut self,
        next: ProcessLifecycleStateV1,
    ) -> Result<(), ProcessContractErrorV1> {
        if self.settlement.is_some() || next.requires_settlement() || !self.state.permits(next) {
            return Err(ProcessContractErrorV1::InvalidLifecycleTransition);
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ProcessContractErrorV1::MetadataOverflow)?;
        self.state = next;
        Ok(())
    }

    /// Returns immutable metadata-only terminal settlement for pure replay.
    #[must_use]
    pub(crate) fn settlement(&self) -> Option<ProcessTerminalSettlementV1> {
        self.settlement.clone()
    }

    /// Atomically records settlement metadata and its exact target lifecycle state.
    pub(crate) fn commit_settlement(
        &mut self,
        settlement: ProcessTerminalSettlementV1,
    ) -> Result<(), ProcessContractErrorV1> {
        if !settlement.matches_claim(&self.input.binding) {
            return Err(ProcessContractErrorV1::GenerationMismatch);
        }
        if let Some(existing) = &self.settlement {
            return if existing.same_draft(&settlement) {
                Ok(())
            } else {
                Err(ProcessContractErrorV1::SettlementConflict)
            };
        }
        let target = settlement.target_state();
        if !self.state.permits(target) {
            return Err(ProcessContractErrorV1::InvalidLifecycleTransition);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ProcessContractErrorV1::MetadataOverflow)?;
        let sequence = self
            .settlement_sequence
            .checked_add(1)
            .ok_or(ProcessContractErrorV1::MetadataOverflow)?;
        self.settlement = Some(settlement.materialize(revision, sequence));
        self.revision = revision;
        self.settlement_sequence = sequence;
        self.state = target;
        Ok(())
    }

    pub(super) fn recover_settlement(
        &mut self,
        settlement: ProcessTerminalSettlementV1,
    ) -> Result<(), ProcessContractErrorV1> {
        if self.state != ProcessLifecycleStateV1::Claimed
            || self.settlement.is_some()
            || settlement.target_state() != ProcessLifecycleStateV1::Uncertain
            || !settlement.matches_claim(&self.input.binding)
        {
            return Err(ProcessContractErrorV1::InvalidLifecycleTransition);
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ProcessContractErrorV1::MetadataOverflow)?;
        let sequence = self
            .settlement_sequence
            .checked_add(1)
            .ok_or(ProcessContractErrorV1::MetadataOverflow)?;
        self.settlement = Some(settlement.materialize(revision, sequence));
        self.revision = revision;
        self.settlement_sequence = sequence;
        self.state = ProcessLifecycleStateV1::Uncertain;
        Ok(())
    }
}

/// Stable adapter boundary for replay-safe claim records.
pub(crate) trait ProcessClaimJournalPort {
    /// Reads one replay-safe record without changing it.
    fn read(
        &self,
        key: &ProcessClaimKeyV1,
    ) -> Result<Option<ProcessClaimRecordV1>, ProcessContractErrorV1>;

    /// Atomically replaces `expected` with `replacement` when it still matches.
    fn compare_and_set(
        &mut self,
        key: &ProcessClaimKeyV1,
        expected: Option<&ProcessClaimRecordV1>,
        replacement: ProcessClaimRecordV1,
    ) -> Result<bool, ProcessContractErrorV1>;
}
