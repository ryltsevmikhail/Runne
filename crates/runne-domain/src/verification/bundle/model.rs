//! Self-reported metadata only; Debug is NOT a safe export format.
use crate::id::{EffectId, IntegrityDigest, InvocationId, PlanId, TaskRunId};
use crate::reference::ResultRef;
use crate::verification::PlanEvaluationRef;
use crate::verification::digest::VerificationDigest;
use crate::verification::identity::{EvidenceRefID, ExportID, ProfileID, RunID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMetadata {
    pub schema_version: u16,
    pub export_id: ExportID,
    pub revision: u64,
    pub producer_version: String,
    pub taskrun_id: TaskRunId,
    pub checked_snapshot: Option<DeclaredSnapshot>,
    pub plan_evaluation: Option<PlanEvaluationRef>,
    pub checks: Vec<ReportedCheck>,
    pub provider_finish: ProviderFinish,
    pub tool_returns: Vec<ReportedToolReturn>,
    pub effects: Vec<ReportedEffect>,
    pub reviewer: ReviewerDisposition,
    pub manual_override: bool,
    pub cost: ReportedCost,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSnapshot {
    pub taskrun_id: TaskRunId,
    pub task_revision: u64,
    pub plan_id: PlanId,
    pub plan_revision: u64,
    pub stream_head: u64,
    pub source_snapshot_digest: IntegrityDigest,
    pub environment: RevisionRef,
    pub required_artifacts: Vec<ArtifactBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRef {
    pub revision: u64,
    pub result: ResultRef,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBinding {
    pub slot: u16,
    pub artifact: RevisionRef,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedCheck {
    pub slot: u16,
    pub binding: Option<DeclaredSnapshot>,
    pub verifier: Option<DeclaredVerifier>,
    pub declared_acceptance: Option<ResultRef>,
    pub result: Option<ResultRef>,
    pub evidence: Vec<EvidenceMetadataRef>,
    pub outcome: ReportedCheckOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredVerifier {
    pub id: String,
    pub version: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceMetadataRef {
    pub evidence_ref_id: EvidenceRefID,
    pub run_id: RunID,
    pub profile_id: ProfileID,
    pub profile_digest: VerificationDigest,
    pub evidence_digest: VerificationDigest,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedToolReturn {
    pub invocation_id: InvocationId,
    pub outcome: ToolReturnOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedEffect {
    pub effect_id: EffectId,
    pub outcome: ReportedEffectOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedCost {
    pub model_compute: CostAmount,
    pub human_review: CostAmount,
    pub recovery: CostAmount,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostAmount {
    KnownUsdMicros(u64),
    Unknown(CostUnknownReason),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostUnknownReason {
    NotCollected,
    Unavailable,
    UnsupportedUnit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedCheckOutcome {
    Passed,
    Failed,
    Partial,
    Uncertain,
    Unsupported,
    NotRun,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFinish {
    Unknown,
    Finished,
    Failed,
    Cancelled,
    NotRun,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolReturnOutcome {
    Unknown,
    Returned { exit_code: Option<i32> },
    Failed,
    NotRun,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedEffectOutcome {
    Unknown,
    NotAttempted,
    Applied,
    NotApplied,
    Failed,
    Uncertain,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewerDisposition {
    Accepted,
    Rejected,
    Pending,
    NotApplicable,
}
