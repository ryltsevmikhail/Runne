//! Durable migration evidence contracts.

use gocode_domain::timestamp::Timestamp;
use sha2::{Digest, Sha256};

use super::types::{ArtifactDigest, CohortSelector, GateFamily, GateId, RuntimeGenerationRef};

/// Durable status of one gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    /// The gate passed for its exact scope and validity window.
    Passed,
    /// The gate failed with a closed reason code.
    Failed {
        /// Machine-distinguishable failure reason.
        code: GateFailureCode,
    },
    /// Previously recorded evidence was revoked.
    Revoked {
        /// Machine-distinguishable revocation reason.
        reason: GateRevocationReason,
    },
}

/// Closed gate failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateFailureCode {
    /// Durable or semantic integrity failed.
    Integrity,
    /// A required component was unavailable.
    Unavailable,
    /// Evidence did not match the requested scope.
    ScopeMismatch,
    /// Policy explicitly denied the operation.
    PolicyDenied,
    /// Evaluation exceeded its allowed time.
    Timeout,
    /// Capacity or SLO requirements were not met.
    Capacity,
    /// Privacy requirements were not met.
    Privacy,
    /// An external or canonical effect remains unresolved.
    UnresolvedEffect,
}

/// Closed reasons why gate evidence can be revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRevocationReason {
    /// Security authority revoked the evidence.
    SecurityRevoked,
    /// A governed artifact changed.
    ArtifactChanged,
    /// One of the scoped runtime generations was replaced.
    GenerationReplaced,
    /// An authorized operator revoked the evidence.
    OperatorRevoked,
}

/// Immutable production-gate evidence scoped to exact runtime artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateEvidence {
    /// Stable identity of the gate.
    pub gate_id: GateId,
    /// Revision of the gate contract.
    pub gate_revision: u16,
    /// Gate family.
    pub family: GateFamily,
    /// Source runtime generation covered by the evidence.
    pub source_generation: RuntimeGenerationRef,
    /// Candidate runtime generation covered by the evidence.
    pub candidate_generation: RuntimeGenerationRef,
    /// Exact cohort covered by the evidence.
    pub cohort: CohortSelector,
    /// Exact contract digest covered by the evidence.
    pub contract_digest: ArtifactDigest,
    /// Exact compatibility-profile digest covered by the evidence.
    pub profile_digest: ArtifactDigest,
    /// Exact configuration digest covered by the evidence.
    pub config_digest: ArtifactDigest,
    /// Time at which the evidence was measured.
    pub measured_at: Timestamp,
    /// Last instant at which the evidence is valid.
    pub valid_until: Timestamp,
    /// Evaluation result.
    pub status: GateStatus,
    /// Digest of the canonical evidence artifact.
    pub evidence_digest: ArtifactDigest,
}

/// Immutable evidence recorded against a migration cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationEvidence {
    /// Pinned source baseline and fixture inventory.
    Baseline {
        /// Full pinned source commit SHA.
        source_sha: String,
        /// Canonical inventory digest.
        inventory_digest: ArtifactDigest,
        /// Sanitized fixture-set digest.
        fixture_digest: ArtifactDigest,
    },
    /// Executable foundation evidence.
    Foundation {
        /// Implemented contract digest.
        contract_digest: ArtifactDigest,
        /// Durable store-integrity evidence digest.
        store_integrity_digest: ArtifactDigest,
        /// Deterministic test evidence digest.
        deterministic_test_digest: ArtifactDigest,
    },
    /// Read-only import and parity evidence.
    ReadOnlyParity {
        /// Import report digest.
        import_report_digest: ArtifactDigest,
        /// Completeness proof digest.
        completeness_digest: ArtifactDigest,
        /// Number of canonical mutations observed.
        canonical_mutation_count: u64,
    },
    /// Pure simulated-shadow evidence.
    SimulatedShadow {
        /// Semantic diff report digest.
        semantic_diff_digest: ArtifactDigest,
        /// Number of canonical writes observed.
        canonical_write_count: u64,
        /// Number of external effects observed.
        external_effect_count: u64,
        /// Number of client acknowledgements observed.
        client_acknowledgement_count: u64,
    },
    /// Evidence for one production gate.
    ProductionGate(GateEvidence),
}

impl MigrationEvidence {
    pub(crate) fn identity_digest(&self) -> ArtifactDigest {
        match self {
            Self::Baseline { fixture_digest, .. } => *fixture_digest,
            Self::Foundation {
                deterministic_test_digest,
                ..
            } => *deterministic_test_digest,
            Self::ReadOnlyParity {
                completeness_digest,
                ..
            } => *completeness_digest,
            Self::SimulatedShadow {
                semantic_diff_digest,
                ..
            } => *semantic_diff_digest,
            Self::ProductionGate(evidence) => evidence.evidence_digest,
        }
    }

    pub(crate) fn semantic_digest(&self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"gocode-migration-evidence\x01");
        match self {
            Self::Baseline {
                source_sha,
                inventory_digest,
                fixture_digest,
            } => {
                hasher.update([1]);
                update_length_prefixed(&mut hasher, source_sha.as_bytes());
                hasher.update(inventory_digest.as_bytes());
                hasher.update(fixture_digest.as_bytes());
            }
            Self::Foundation {
                contract_digest,
                store_integrity_digest,
                deterministic_test_digest,
            } => {
                hasher.update([2]);
                hasher.update(contract_digest.as_bytes());
                hasher.update(store_integrity_digest.as_bytes());
                hasher.update(deterministic_test_digest.as_bytes());
            }
            Self::ReadOnlyParity {
                import_report_digest,
                completeness_digest,
                canonical_mutation_count,
            } => {
                hasher.update([3]);
                hasher.update(import_report_digest.as_bytes());
                hasher.update(completeness_digest.as_bytes());
                hasher.update(canonical_mutation_count.to_be_bytes());
            }
            Self::SimulatedShadow {
                semantic_diff_digest,
                canonical_write_count,
                external_effect_count,
                client_acknowledgement_count,
            } => {
                hasher.update([4]);
                hasher.update(semantic_diff_digest.as_bytes());
                hasher.update(canonical_write_count.to_be_bytes());
                hasher.update(external_effect_count.to_be_bytes());
                hasher.update(client_acknowledgement_count.to_be_bytes());
            }
            Self::ProductionGate(evidence) => {
                hasher.update([5]);
                update_length_prefixed(&mut hasher, evidence.gate_id.as_str().as_bytes());
                hasher.update(evidence.gate_revision.to_be_bytes());
                hasher.update([evidence.family as u8]);
                update_length_prefixed(&mut hasher, evidence.source_generation.as_str().as_bytes());
                update_length_prefixed(
                    &mut hasher,
                    evidence.candidate_generation.as_str().as_bytes(),
                );
                hasher.update((evidence.cohort.dimensions().len() as u16).to_be_bytes());
                for dimension in evidence.cohort.dimensions() {
                    update_length_prefixed(&mut hasher, dimension.key().as_bytes());
                    update_length_prefixed(&mut hasher, dimension.value().as_bytes());
                }
                hasher.update(evidence.contract_digest.as_bytes());
                hasher.update(evidence.profile_digest.as_bytes());
                hasher.update(evidence.config_digest.as_bytes());
                hasher.update(evidence.measured_at.as_unix_micros().to_be_bytes());
                hasher.update(evidence.valid_until.as_unix_micros().to_be_bytes());
                match evidence.status {
                    GateStatus::Passed => hasher.update([1]),
                    GateStatus::Failed { code } => hasher.update([2, gate_failure_tag(code)]),
                    GateStatus::Revoked { reason } => {
                        hasher.update([3, gate_revocation_tag(reason)]);
                    }
                }
                hasher.update(evidence.evidence_digest.as_bytes());
            }
        }
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
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
