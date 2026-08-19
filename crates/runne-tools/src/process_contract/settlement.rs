//! Unified metadata-only terminal settlement contracts.

use core::fmt;

use runne_platform_ports::process::{
    NoProcessStartedEvidenceV1, ProcessOwnerVerificationV1, ProcessTerminalEvidenceV1,
    ProcessTreeCleanupV1,
};

use super::{
    ProcessClaimBindingV1, ProcessContractErrorV1, ProcessOutputEvidenceV1,
    TransientProcessOutputChannelV1,
};

/// Closed reason why the exact process effect cannot be proved terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessUncertainReasonV1 {
    /// Required lifecycle or terminal evidence was unavailable.
    EvidenceUnavailable,
    /// Terminal output evidence could not be read within the sealed source contract.
    OutputEvidenceUnavailable,
    /// The monotonic clock could not establish a valid timing disposition.
    TimingUnavailable,
    /// Exact process-tree cleanup could not be verified.
    TreeCleanupUnverified,
    /// Restart recovery found a nonterminal persisted process projection.
    RecoveryRequired,
}

/// Metadata-only terminal result with an optional first-return transient output channel.
pub struct ProcessTerminalResultV1 {
    settlement: ProcessTerminalSettlementV1,
    transient: Option<TransientProcessOutputChannelV1>,
}

impl ProcessTerminalResultV1 {
    pub(super) fn first(
        settlement: ProcessTerminalSettlementV1,
        transient: TransientProcessOutputChannelV1,
    ) -> Self {
        Self {
            settlement,
            transient: Some(transient),
        }
    }

    pub(super) fn replay(settlement: ProcessTerminalSettlementV1) -> Self {
        Self {
            settlement,
            transient: None,
        }
    }

    /// Returns immutable persisted settlement metadata.
    #[must_use]
    pub const fn settlement(&self) -> &ProcessTerminalSettlementV1 {
        &self.settlement
    }

    /// Returns the raw transient channel only on the first authorized completed return.
    #[must_use]
    pub(crate) const fn transient(&self) -> Option<&TransientProcessOutputChannelV1> {
        self.transient.as_ref()
    }
}

impl PartialEq for ProcessTerminalResultV1 {
    fn eq(&self, other: &Self) -> bool {
        self.settlement == other.settlement
    }
}

impl Eq for ProcessTerminalResultV1 {}

impl fmt::Debug for ProcessTerminalResultV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessTerminalResultV1(redacted)")
    }
}

/// Closed monotonic timing disposition attached to terminal settlement metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMonotonicTimingDispositionV1 {
    /// Settlement occurred while the approved monotonic deadline remained live.
    WithinDeadline,
    /// Settlement followed an approved monotonic deadline boundary.
    DeadlineReached,
    /// Explicit cancellation was observed before the approved deadline.
    CancellationObservedBeforeDeadline,
    /// Monotonic timing could not be established and the result is uncertain.
    TimingUncertain,
}

/// Exact terminal proof or a closed reason that proof cannot be established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessSettlementProofV1 {
    /// The platform proved that no process started for the exact lifecycle binding.
    NotStarted(NoProcessStartedEvidenceV1),
    /// The platform proved terminal completion for the exact lifecycle binding.
    Completed(ProcessTerminalEvidenceV1),
    /// The effect cannot be proven because one closed uncertainty reason applies.
    Uncertain(ProcessUncertainReasonV1),
}

/// Metadata-only atomic terminal settlement for one exact claim projection.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessTerminalSettlementV1 {
    binding: ProcessClaimBindingV1,
    proof: ProcessSettlementProofV1,
    output: ProcessOutputEvidenceV1,
    timing: ProcessMonotonicTimingDispositionV1,
    tree_cleanup: ProcessTreeCleanupV1,
    owner_verification: ProcessOwnerVerificationV1,
    revision: u64,
    sequence: u64,
}

impl ProcessTerminalSettlementV1 {
    pub(crate) fn new(
        binding: &ProcessClaimBindingV1,
        proof: ProcessSettlementProofV1,
        output: ProcessOutputEvidenceV1,
        timing: ProcessMonotonicTimingDispositionV1,
        tree_cleanup: ProcessTreeCleanupV1,
        owner_verification: ProcessOwnerVerificationV1,
    ) -> Result<Self, ProcessContractErrorV1> {
        let dispositions_valid = match &proof {
            ProcessSettlementProofV1::NotStarted(_) => {
                owner_verification == ProcessOwnerVerificationV1::NotApplicable
                    && tree_cleanup == ProcessTreeCleanupV1::NotApplicable
            }
            ProcessSettlementProofV1::Completed(_) => {
                owner_verification == ProcessOwnerVerificationV1::Verified
                    && tree_cleanup == ProcessTreeCleanupV1::Verified
            }
            ProcessSettlementProofV1::Uncertain(_) => true,
        };
        if !dispositions_valid {
            return Err(ProcessContractErrorV1::EvidenceMalformed);
        }
        Ok(Self {
            binding: binding.clone(),
            proof,
            output,
            timing,
            tree_cleanup,
            owner_verification,
            revision: 0,
            sequence: 0,
        })
    }

    /// Returns the closed proof or uncertainty reason without raw process data.
    #[must_use]
    pub const fn proof(&self) -> &ProcessSettlementProofV1 {
        &self.proof
    }

    /// Returns bounded metadata for captured output only.
    #[must_use]
    pub const fn output(&self) -> &ProcessOutputEvidenceV1 {
        &self.output
    }

    /// Returns the monotonic timing disposition.
    #[must_use]
    pub const fn timing(&self) -> ProcessMonotonicTimingDispositionV1 {
        self.timing
    }

    /// Returns whether exact owned-tree cleanup was verified.
    #[must_use]
    pub const fn tree_cleanup(&self) -> ProcessTreeCleanupV1 {
        self.tree_cleanup
    }

    /// Returns the exact owner-verification result.
    #[must_use]
    pub const fn owner_verification(&self) -> ProcessOwnerVerificationV1 {
        self.owner_verification
    }

    /// Returns the settlement revision supplied by the authoritative journal.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the settlement sequence supplied by the authoritative journal.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) fn matches_claim(&self, claim: &ProcessClaimBindingV1) -> bool {
        if self.binding != *claim {
            return false;
        }
        match &self.proof {
            ProcessSettlementProofV1::NotStarted(evidence) => {
                ProcessClaimBindingV1::from_lifecycle(evidence.binding()) == *claim
            }
            ProcessSettlementProofV1::Completed(evidence) => {
                ProcessClaimBindingV1::from_lifecycle(evidence.binding()) == *claim
            }
            ProcessSettlementProofV1::Uncertain(_) => true,
        }
    }

    pub(super) fn materialize(mut self, revision: u64, sequence: u64) -> Self {
        self.revision = revision;
        self.sequence = sequence;
        self
    }

    pub(super) fn same_draft(&self, draft: &Self) -> bool {
        self.binding == draft.binding
            && self.proof == draft.proof
            && self.output == draft.output
            && self.timing == draft.timing
            && self.tree_cleanup == draft.tree_cleanup
            && self.owner_verification == draft.owner_verification
    }

    pub(super) const fn target_state(&self) -> super::ProcessLifecycleStateV1 {
        match &self.proof {
            ProcessSettlementProofV1::NotStarted(_) => super::ProcessLifecycleStateV1::NotStarted,
            ProcessSettlementProofV1::Completed(_) => super::ProcessLifecycleStateV1::Completed,
            ProcessSettlementProofV1::Uncertain(_) => super::ProcessLifecycleStateV1::Uncertain,
        }
    }
}

impl fmt::Debug for ProcessTerminalSettlementV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessTerminalSettlementV1(redacted)")
    }
}
