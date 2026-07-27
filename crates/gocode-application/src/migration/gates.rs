//! Durable migration evidence contracts.

use gocode_domain::timestamp::Timestamp;
use sha2::{Digest, Sha256};

use super::{
    state::MigrationPhase,
    types::{ArtifactDigest, CohortSelector, GateFamily, GateId, RuntimeGenerationRef},
};

/// Critical evidence families required before entering Internal Canary.
pub const PHASE_4: &[GateFamily] = &[
    GateFamily::StoreIntegrity,
    GateFamily::CanonicalAudit,
    GateFamily::SecurityPolicy,
    GateFamily::PlatformCertification,
    GateFamily::RuntimeHealth,
    GateFamily::RecoveryReadiness,
    GateFamily::DrainReadiness,
    GateFamily::RollbackReadiness,
    GateFamily::CapacitySlo,
    GateFamily::ShadowIsolation,
];
/// Critical evidence families required for each bounded cohort expansion.
pub const PHASE_5: &[GateFamily] = PHASE_4;

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

/// Exact runtime, cohort, artifact and time scope required by a gate policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateContext {
    /// Source runtime generation being evaluated.
    pub source_generation: RuntimeGenerationRef,
    /// Candidate runtime generation being evaluated.
    pub candidate_generation: RuntimeGenerationRef,
    /// Exact routing cohort being evaluated.
    pub cohort: CohortSelector,
    /// Canonical contract digest required by the transition.
    pub contract_digest: ArtifactDigest,
    /// Compatibility-profile digest required by the transition.
    pub profile_digest: ArtifactDigest,
    /// Runtime configuration digest required by the transition.
    pub config_digest: ArtifactDigest,
    /// Evaluation instant supplied by the application authority.
    pub now: Timestamp,
}

/// Reason immutable gate evidence cannot satisfy an exact gate context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateApplicabilityError {
    /// The evidence validity window has not started.
    NotYetValid,
    /// The evidence validity window has ended.
    Expired,
    /// The recorded gate evaluation failed.
    Failed,
    /// The evidence was explicitly revoked.
    Revoked,
    /// The evidence covers a different source runtime generation.
    SourceGenerationMismatch,
    /// The evidence covers a different candidate runtime generation.
    CandidateGenerationMismatch,
    /// The evidence covers a different routing cohort.
    CohortMismatch,
    /// The contract digest differs from the requested scope.
    ContractDigestMismatch,
    /// The compatibility-profile digest differs from the requested scope.
    ProfileDigestMismatch,
    /// The runtime configuration digest differs from the requested scope.
    ConfigDigestMismatch,
    /// The evidence artifact digest is the all-zero sentinel.
    EmptyEvidenceDigest,
}

impl GateEvidence {
    /// Validate this immutable evidence against an exact gate context.
    pub fn applies_to(&self, context: &GateContext) -> Result<(), GateApplicabilityError> {
        match self.status {
            GateStatus::Passed => {}
            GateStatus::Failed { .. } => return Err(GateApplicabilityError::Failed),
            GateStatus::Revoked { .. } => return Err(GateApplicabilityError::Revoked),
        }
        if self.measured_at > context.now {
            return Err(GateApplicabilityError::NotYetValid);
        }
        if self.valid_until <= context.now {
            return Err(GateApplicabilityError::Expired);
        }
        if self.source_generation != context.source_generation {
            return Err(GateApplicabilityError::SourceGenerationMismatch);
        }
        if self.candidate_generation != context.candidate_generation {
            return Err(GateApplicabilityError::CandidateGenerationMismatch);
        }
        if self.cohort != context.cohort {
            return Err(GateApplicabilityError::CohortMismatch);
        }
        if self.contract_digest != context.contract_digest {
            return Err(GateApplicabilityError::ContractDigestMismatch);
        }
        if self.profile_digest != context.profile_digest {
            return Err(GateApplicabilityError::ProfileDigestMismatch);
        }
        if self.config_digest != context.config_digest {
            return Err(GateApplicabilityError::ConfigDigestMismatch);
        }
        if self.evidence_digest.as_bytes() == &[0; 32] {
            return Err(GateApplicabilityError::EmptyEvidenceDigest);
        }
        Ok(())
    }
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

/// Immutable gate policy for one production phase boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseGatePolicy {
    target: MigrationPhase,
    revision: u16,
    required: &'static [GateFamily],
}

impl PhaseGatePolicy {
    /// Resolve the currently implemented policy for a production phase.
    pub const fn for_target(target: MigrationPhase) -> Option<Self> {
        match target {
            MigrationPhase::InternalCanary => Some(Self {
                target,
                revision: 1,
                required: PHASE_4,
            }),
            MigrationPhase::CohortRollout => Some(Self {
                target,
                revision: 2,
                required: PHASE_5,
            }),
            MigrationPhase::Baseline
            | MigrationPhase::Foundation
            | MigrationPhase::ReadOnlyParity
            | MigrationPhase::SimulatedShadow
            | MigrationPhase::DefaultNative
            | MigrationPhase::DrainDeprecate
            | MigrationPhase::Retired => None,
        }
    }

    /// Production phase protected by this policy.
    pub const fn target(self) -> MigrationPhase {
        self.target
    }

    /// Stable revision of the phase policy.
    pub const fn revision(self) -> u16 {
        self.revision
    }

    /// Gate families required by this policy in canonical order.
    pub const fn required(self) -> &'static [GateFamily] {
        self.required
    }

    /// Select and validate the latest evidence for every required family.
    pub fn validate(
        self,
        history: &[MigrationEvidence],
        context: &GateContext,
    ) -> Result<ValidatedGateSet, GateSetValidationError> {
        let mut members = Vec::with_capacity(self.required.len());
        for family in self.required {
            let evidence = history.iter().rev().find_map(|evidence| {
                let MigrationEvidence::ProductionGate(gate) = evidence else {
                    return None;
                };
                (gate.family == *family).then_some(gate)
            });
            let evidence = evidence.ok_or(GateSetValidationError::Missing { family: *family })?;
            evidence.applies_to(context).map_err(|reason| {
                GateSetValidationError::Inapplicable {
                    family: *family,
                    reason,
                }
            })?;
            members.push(evidence.clone());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"gocode-migration-gate-set\x01");
        hasher.update([migration_phase_tag(self.target)]);
        hasher.update(self.revision.to_be_bytes());
        for evidence in &members {
            hasher.update([evidence.family as u8]);
            hasher.update(
                MigrationEvidence::ProductionGate(evidence.clone())
                    .semantic_digest()
                    .as_bytes(),
            );
        }
        Ok(ValidatedGateSet {
            target: self.target,
            policy_revision: self.revision,
            members,
            digest: ArtifactDigest::from_bytes(hasher.finalize().into()),
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::types::CohortDimension;

    #[test]
    fn stale_revoked_and_scope_mismatched_evidence_never_applies() {
        let context = gate_context_at(200);

        let mut expired = passed_evidence();
        expired.valid_until = Timestamp::from_unix_micros(200);
        assert_eq!(
            expired.applies_to(&context),
            Err(GateApplicabilityError::Expired)
        );

        let mut revoked = passed_evidence();
        revoked.status = GateStatus::Revoked {
            reason: GateRevocationReason::SecurityRevoked,
        };
        assert_eq!(
            revoked.applies_to(&context),
            Err(GateApplicabilityError::Revoked)
        );

        let mut wrong_candidate = passed_evidence();
        wrong_candidate.candidate_generation =
            RuntimeGenerationRef::new("candidate-other").unwrap();
        assert_eq!(
            wrong_candidate.applies_to(&context),
            Err(GateApplicabilityError::CandidateGenerationMismatch)
        );
    }

    #[test]
    fn all_ten_families_have_stable_discriminants() {
        assert_eq!(
            GateFamily::ALL,
            [
                GateFamily::StoreIntegrity,
                GateFamily::CanonicalAudit,
                GateFamily::SecurityPolicy,
                GateFamily::PlatformCertification,
                GateFamily::RuntimeHealth,
                GateFamily::RecoveryReadiness,
                GateFamily::DrainReadiness,
                GateFamily::RollbackReadiness,
                GateFamily::CapacitySlo,
                GateFamily::ShadowIsolation,
            ]
        );
    }

    #[test]
    fn cohort_rollout_uses_a_distinct_policy_revision_with_all_critical_families() {
        let canary = PhaseGatePolicy::for_target(MigrationPhase::InternalCanary).unwrap();
        let cohort = PhaseGatePolicy::for_target(MigrationPhase::CohortRollout).unwrap();

        assert_eq!(canary.revision(), 1);
        assert_eq!(cohort.revision(), 2);
        assert_eq!(cohort.required(), PHASE_4);
    }

    #[test]
    fn applicability_requires_a_passed_fresh_exact_nonempty_scope() {
        let context = gate_context_at(200);
        assert_eq!(passed_evidence().applies_to(&context), Ok(()));

        let mut evidence = passed_evidence();
        evidence.measured_at = Timestamp::from_unix_micros(201);
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::NotYetValid)
        );

        let mut evidence = passed_evidence();
        evidence.status = GateStatus::Failed {
            code: GateFailureCode::Integrity,
        };
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::Failed)
        );

        let mut evidence = passed_evidence();
        evidence.source_generation = RuntimeGenerationRef::new("source-other").unwrap();
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::SourceGenerationMismatch)
        );

        let mut evidence = passed_evidence();
        evidence.cohort = CohortSelector::new(vec![
            CohortDimension::new("project_class", "external").unwrap(),
        ])
        .unwrap();
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::CohortMismatch)
        );

        let mismatched_digests = [
            (
                ArtifactDigest::from_bytes([12; 32]),
                context.profile_digest,
                context.config_digest,
                GateApplicabilityError::ContractDigestMismatch,
            ),
            (
                context.contract_digest,
                ArtifactDigest::from_bytes([13; 32]),
                context.config_digest,
                GateApplicabilityError::ProfileDigestMismatch,
            ),
            (
                context.contract_digest,
                context.profile_digest,
                ArtifactDigest::from_bytes([14; 32]),
                GateApplicabilityError::ConfigDigestMismatch,
            ),
        ];
        for (contract, profile, config, expected) in mismatched_digests {
            let mut evidence = passed_evidence();
            evidence.contract_digest = contract;
            evidence.profile_digest = profile;
            evidence.config_digest = config;
            assert_eq!(evidence.applies_to(&context), Err(expected));
        }

        let mut evidence = passed_evidence();
        evidence.evidence_digest = ArtifactDigest::from_bytes([0; 32]);
        assert_eq!(
            evidence.applies_to(&context),
            Err(GateApplicabilityError::EmptyEvidenceDigest)
        );
    }

    fn gate_context_at(now: i64) -> GateContext {
        GateContext {
            source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
            candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
            cohort: cohort(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            now: Timestamp::from_unix_micros(now),
        }
    }

    fn passed_evidence() -> GateEvidence {
        GateEvidence {
            gate_id: GateId::new("gate-1").unwrap(),
            gate_revision: 1,
            family: GateFamily::StoreIntegrity,
            source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
            candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
            cohort: cohort(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            measured_at: Timestamp::from_unix_micros(100),
            valid_until: Timestamp::from_unix_micros(300),
            status: GateStatus::Passed,
            evidence_digest: ArtifactDigest::from_bytes([5; 32]),
        }
    }

    fn cohort() -> CohortSelector {
        CohortSelector::new(vec![
            CohortDimension::new("project_class", "internal").unwrap(),
        ])
        .unwrap()
    }
}
