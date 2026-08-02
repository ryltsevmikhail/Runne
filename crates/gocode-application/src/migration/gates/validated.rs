/// A complete applicable evidence set in canonical family order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGateSet {
    target: MigrationPhase,
    policy_revision: u16,
    members: Vec<GateEvidence>,
    digest: ArtifactDigest,
}

impl ValidatedGateSet {
    /// Production phase authorized by this evidence set.
    pub const fn target(&self) -> MigrationPhase {
        self.target
    }

    /// Stable policy revision used during validation.
    pub const fn policy_revision(&self) -> u16 {
        self.policy_revision
    }

    /// Applicable gate evidence in canonical family order.
    pub fn members(&self) -> &[GateEvidence] {
        &self.members
    }

    /// Canonical digest frozen by cutover preparation.
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }
}

/// Failure selecting an applicable evidence set for a phase policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateSetValidationError {
    /// No evidence exists for a required family.
    Missing {
        /// Missing critical family.
        family: GateFamily,
    },
    /// Latest evidence for a required family is not applicable.
    Inapplicable {
        /// Inapplicable critical family.
        family: GateFamily,
        /// Exact applicability failure.
        reason: GateApplicabilityError,
    },
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn migration_phase_tag(phase: MigrationPhase) -> u8 {
    match phase {
        MigrationPhase::Baseline => 0,
        MigrationPhase::Foundation => 1,
        MigrationPhase::ReadOnlyParity => 2,
        MigrationPhase::SimulatedShadow => 3,
        MigrationPhase::InternalCanary => 4,
        MigrationPhase::CohortRollout => 5,
        MigrationPhase::DefaultNative => 6,
        MigrationPhase::DrainDeprecate => 7,
        MigrationPhase::Retired => 8,
    }
}

fn gate_failure_tag(code: GateFailureCode) -> u8 {
    match code {
        GateFailureCode::Integrity => 1,
        GateFailureCode::Unavailable => 2,
        GateFailureCode::ScopeMismatch => 3,
        GateFailureCode::PolicyDenied => 4,
        GateFailureCode::Timeout => 5,
        GateFailureCode::Capacity => 6,
        GateFailureCode::Privacy => 7,
        GateFailureCode::UnresolvedEffect => 8,
    }
}

fn gate_revocation_tag(reason: GateRevocationReason) -> u8 {
    match reason {
        GateRevocationReason::SecurityRevoked => 1,
        GateRevocationReason::ArtifactChanged => 2,
        GateRevocationReason::GenerationReplaced => 3,
        GateRevocationReason::OperatorRevoked => 4,
    }
}
