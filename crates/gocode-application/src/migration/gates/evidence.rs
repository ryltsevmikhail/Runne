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
/// Critical evidence families required before candidate becomes default.
pub const PHASE_6: &[GateFamily] = PHASE_4;

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
