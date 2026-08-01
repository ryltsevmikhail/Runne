/// Durable drain evidence referenced by a cutover manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReportArtifact {
    pub report: ArtifactRef,
    pub complete: bool,
    pub timed_out: bool,
    pub unresolved_effects: u64,
    pub source_high_water: u64,
}

/// Durable candidate rebuild/validation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateValidationReport {
    pub report: ArtifactRef,
    pub validation: ArtifactValidation,
}

/// Closed rollback policy frozen before a routing CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackPolicy {
    /// Rollback before candidate writes may reuse a verified retained source.
    BeforeCandidateWrites,
    /// Candidate writes require an exact reverse migration contract.
    ReverseMigrationRequired(ArtifactRef),
    /// Automatic rollback is unavailable.
    ManualOnly,
}

/// Complete construction fields for a cutover manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutoverManifestFields {
    pub manifest: ArtifactRef,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub intent: CutoverIntent,
    pub rollout_policy: CutoverPolicy,
    pub routing_unit: RoutingUnit,
    pub source_release: ArtifactRef,
    pub source_generation: RuntimeGenerationRef,
    pub candidate_release: ArtifactRef,
    pub candidate_generation: RuntimeGenerationRef,
    pub frozen_evidence_set: ArtifactRef,
    pub migration_report: MigrationReport,
    pub drain_report: DrainReportArtifact,
    pub candidate_validation: CandidateValidationReport,
    pub expected_routing_generation: RoutingGeneration,
    pub routing_generation_at_prepare: RoutingGeneration,
    pub rollback_policy: RollbackPolicy,
    pub retention_until: Timestamp,
    pub operator_authorization: ArtifactRef,
    pub prepared_transition_id: String,
    pub expected_plan_version: u64,
    pub prepared_plan_version: u64,
    pub prepared_at: Timestamp,
}

/// Immutable cutover authorization persisted before any routing CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutoverManifest {
    pub manifest_digest: ArtifactDigest,
    pub manifest_ref: String,
    pub plan_id: MigrationPlanId,
    pub cycle_id: MigrationCycleId,
    pub intent: CutoverIntent,
    pub rollout_policy: CutoverPolicy,
    pub routing_unit: RoutingUnit,
    pub source_release: ArtifactRef,
    pub source_generation: RuntimeGenerationRef,
    pub candidate_release: ArtifactRef,
    pub candidate_generation: RuntimeGenerationRef,
    pub evidence_set_digest: ArtifactDigest,
    pub evidence_set_ref: String,
    pub import_report: ArtifactRef,
    pub drain_report: ArtifactRef,
    pub candidate_validation: ArtifactRef,
    pub source_high_water: u64,
    pub expected_routing_generation: RoutingGeneration,
    pub rollback_policy: RollbackPolicy,
    pub retention_until: Timestamp,
    pub operator_authorization: ArtifactRef,
    pub prepared_transition_id: String,
    pub expected_plan_version: u64,
    pub plan_version: u64,
    pub prepared_at: Timestamp,
}
