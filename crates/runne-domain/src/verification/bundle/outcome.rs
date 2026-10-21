//! Structural support is presence/consistency, never verification or authority.
use super::model::ReportedCheckOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingComponent {
    CheckedSnapshot,
    ComparisonSnapshot,
    CheckBinding,
    Verifier,
    DeclaredAcceptance,
    ResultRef,
    EvidenceRefs,
    PlanEvaluationRef,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralSupport {
    Complete,
    Incomplete,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedHistoricalCheck {
    pub slot: u16,
    pub reported_outcome: ReportedCheckOutcome,
    pub structural_support: StructuralSupport,
    pub missing: Vec<MissingComponent>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralReport {
    pub historical_checks: Vec<ScopedHistoricalCheck>,
    pub missing: Vec<MissingComponent>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingAxis {
    TaskRevision,
    PlanRevision,
    StreamHead,
    SourceSnapshot,
    Environment,
    RequiredArtifacts,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredSnapshotBinding {
    MatchesDeclaredSnapshot,
    StaleAgainstDeclaredSnapshot { changed: Vec<BindingAxis> },
    Unknown { missing: Vec<MissingComponent> },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityResolution {
    NotPerformed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentApplicability {
    UnknownWithoutE2,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleProjection {
    pub historical_checks: Vec<ScopedHistoricalCheck>,
    pub declared_snapshot_binding: DeclaredSnapshotBinding,
    pub authority_resolution: AuthorityResolution,
    pub current_applicability: CurrentApplicability,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleErrorCode {
    UnsupportedSchema,
    InvalidRevision,
    InvalidIdentity,
    InvalidString,
    TooManyChecks,
    TooManyArtifacts,
    TooManyEvidenceRefs,
    TooManyToolReturns,
    TooManyEffects,
    CheckOrder,
    ArtifactOrder,
    EvidenceOrder,
    ToolOrder,
    EffectOrder,
    SnapshotTaskMismatch,
    CheckBindingMismatch,
    PlanEvaluationMismatch,
    EvidenceScopeMismatch,
    ComparisonScopeMismatch,
}
/// Ordinal is the zero-based collection item (or zero for a bundle-level error).
/// Never contains rejected values or references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleError {
    pub code: BundleErrorCode,
    pub ordinal: usize,
}
