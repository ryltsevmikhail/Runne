/// Input for staging a migration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlanInput {
    /// Baseline plan.
    pub plan: MigrationPlan,
    /// Initial Source-authoritative routing snapshot.
    pub initial_snapshot: RoutingSnapshot,
}

/// Successful stage result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlanOutput {
    /// Staged plan.
    pub plan: MigrationPlan,
    /// Initial Source-authoritative routing snapshot.
    pub snapshot: RoutingSnapshot,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Input for recording immutable evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEvidenceInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Evidence to append.
    pub evidence: MigrationEvidence,
}

/// Successful evidence append result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEvidenceOutput {
    /// Updated plan version.
    pub plan: MigrationPlan,
    /// Durable mutation identity.
    pub transition_id: String,
}

/// Successful phase advance result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancePhaseOutput {
    /// Updated plan.
    pub plan: MigrationPlan,
    /// Routing snapshot committed by the operation, if any.
    pub snapshot: Option<RoutingSnapshot>,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Input for preparing a cutover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareCutoverInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Exact rollout intent.
    pub intent: CutoverIntent,
    /// Exact phase-specific rollout policy.
    pub rollout_policy: CutoverPolicy,
    /// Immutable content-addressed manifest identity.
    pub manifest: ArtifactRef,
    /// Exact source release artifact.
    pub source_release: ArtifactRef,
    /// Exact candidate release artifact.
    pub candidate_release: ArtifactRef,
    /// Frozen production gate set.
    pub frozen_evidence_set: ArtifactRef,
    /// Immutable one-way import report.
    pub migration_report: MigrationReport,
    /// Complete drain evidence.
    pub drain_report: DrainReportArtifact,
    /// Candidate rebuild and validation evidence.
    pub candidate_validation: CandidateValidationReport,
    /// Rollback policy frozen before routing CAS.
    pub rollback_policy: RollbackPolicy,
    /// Retention deadline for rollback artifacts.
    pub retention_until: gocode_domain::timestamp::Timestamp,
    /// Operator authorization evidence.
    pub operator_authorization: ArtifactRef,
}

/// Prepared cutover result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareCutoverOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for committing a prepared cutover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCutoverInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Identity returned by preparation.
    pub prepared_transition_id: String,
    /// Source high-water observed immediately before routing CAS.
    pub observed_source_high_water: u64,
    /// Fresh fence token assigned to the candidate routing generation.
    pub candidate_fencing_token: FencingToken,
}

/// Committed cutover result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCutoverOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for starting a rollback cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRollbackInput {
    /// Parent forward or rollback plan.
    pub parent_plan_id: MigrationPlanId,
    /// New isolated rollback plan.
    pub rollback_plan: MigrationPlan,
    /// Source-authoritative rollback snapshot.
    pub initial_snapshot: RoutingSnapshot,
}

/// Successful rollback-cycle creation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRollbackOutput {
    /// New rollback plan.
    pub plan: MigrationPlan,
    /// Initial Source-authoritative rollback snapshot.
    pub snapshot: RoutingSnapshot,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Input for beginning cohort drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDrainInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Exact cohort whose admission must close.
    pub cohort: CohortSelector,
}

/// Successful drain-start result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDrainOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for retiring source authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireSourceInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Immutable final retirement manifest.
    pub manifest: RetirementManifest,
    /// Evaluated complete exit-condition set.
    pub readiness: RetirementReadiness,
}

/// Successful source-retirement result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireSourceOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for emergency candidate authority revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRevokeInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Operator authorization evidence.
    pub operator_authorization: ArtifactRef,
    /// Machine-readable emergency reason.
    pub emergency_reason: String,
    /// Fresh fence token for the restored Source generation.
    pub new_fencing_token: FencingToken,
}

/// Successful emergency revocation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRevokeOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}
