//! Bounded self-reported metadata, not proof, authority, or a safe export.
mod constraints;
mod model;
mod outcome;
mod project;
mod validate;
pub use project::project_declared_snapshot;
#[cfg(test)]
mod projection_tests;

pub use model::{
    ArtifactBinding, BundleMetadata, CostAmount, CostUnknownReason, DeclaredSnapshot,
    DeclaredVerifier, EvidenceMetadataRef, ProviderFinish, ReportedCheck, ReportedCheckOutcome,
    ReportedCost, ReportedEffect, ReportedEffectOutcome, ReportedToolReturn, ReviewerDisposition,
    RevisionRef, ToolReturnOutcome,
};
pub use outcome::{
    AuthorityResolution, BindingAxis, BundleError, BundleErrorCode, BundleProjection,
    CurrentApplicability, DeclaredSnapshotBinding, MissingComponent, ScopedHistoricalCheck,
    StructuralReport, StructuralSupport,
};
pub use validate::validate_structure;

#[cfg(test)]
mod boundary_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod validation_tests;
