//! Data-only scope comparisons; compatibility never admits an effect.
use super::RetainedRelevantSemanticsV1;
use crate::{
    permission_modes::CompositeEffectScope,
    project_trust::{ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId},
};

/// Valid original data may lie outside the proven retained subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedScopeSemanticsV1 {
    /// Exact existing provided-class projection.
    SupportedV1(RetainedRelevantSemanticsV1),
    /// Representation is valid, but no retained equivalence is established.
    UnsupportedV1(OutsideProvenRetainedSubset),
}

/// The current classifier proves no equivalence for this valid shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutsideProvenRetainedSubset;

/// Invalid original data is distinct from a valid unsupported shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidOriginalSemanticsV1 {
    /// Scope or project-bound Closed coverage is invalid.
    InvalidScope,
    /// The original snapshot is malformed.
    InvalidSnapshot,
    /// A frozen semantic input version is unknown.
    UnsupportedVersion,
}

/// Pure comparison output, carrying no owner, clock, proof or permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedScopeCompatibilityV1 {
    /// Relevant semantics agree; live authority checks are still mandatory.
    Compatible {
        original: RetainedRelevantSemanticsV1,
        current: RetainedRelevantSemanticsV1,
    },
    /// A provided class changed its policy decision.
    RelevantChange,
    /// Project, scope shape or trust-owner identity changed.
    IdentityChanged,
    /// At least one valid scope is outside the proven subset.
    Unsupported,
    /// Input data or versions are invalid.
    Invalid,
}

/// Derives original semantics without fabricating admission evidence.
pub fn derive_original_semantics_v1(
    project: ProjectTrustProjectId,
    scope: &CompositeEffectScope,
    snapshot: &ProjectTrustEffectPolicySnapshot,
    preset_version: u16,
    source_policy_version: u64,
    command_policy_version: u64,
) -> Result<RetainedScopeSemanticsV1, InvalidOriginalSemanticsV1> {
    use InvalidOriginalSemanticsV1::{InvalidScope, InvalidSnapshot, UnsupportedVersion};
    if preset_version != 1
        || source_policy_version != crate::project_trust::FROZEN_POLICY_VERSION
        || command_policy_version != crate::project_trust::LOCAL_COMMAND_POLICY_VERSION
    {
        return Err(UnsupportedVersion);
    }
    if !snapshot.is_valid() {
        return Err(InvalidSnapshot);
    }
    scope.validate().map_err(|_| InvalidScope)?;
    let coverage =
        crate::permission_modes::ManagedPolicyCoverage::from_closed_snapshot(project, snapshot)
            .ok_or(InvalidScope)?;
    if coverage != scope.managed_policy {
        return Err(InvalidScope);
    }
    let Some(provided) = super::provided_classes::retained_provided_classes(scope) else {
        return Ok(RetainedScopeSemanticsV1::UnsupportedV1(
            OutsideProvenRetainedSubset,
        ));
    };
    let semantics = super::semantics::retained_relevant_semantics(
        snapshot,
        provided,
        preset_version,
        source_policy_version,
        command_policy_version,
    )
    .ok_or(UnsupportedVersion)?;
    Ok(RetainedScopeSemanticsV1::SupportedV1(semantics))
}

/// Assesses data compatibility only, never mode, expiry or human authority.
#[allow(clippy::too_many_arguments)]
pub fn assess_retained_scope_compatibility_v1(
    original_project: ProjectTrustProjectId,
    original_scope: &CompositeEffectScope,
    original_snapshot: &ProjectTrustEffectPolicySnapshot,
    current_project: ProjectTrustProjectId,
    current_scope: &CompositeEffectScope,
    current_snapshot: &ProjectTrustEffectPolicySnapshot,
    preset_version: u16,
    source_policy_version: u64,
    command_policy_version: u64,
) -> RetainedScopeCompatibilityV1 {
    use RetainedScopeCompatibilityV1::{
        Compatible, IdentityChanged, Invalid, RelevantChange, Unsupported,
    };
    let derive = |project, scope, snapshot| {
        derive_original_semantics_v1(
            project,
            scope,
            snapshot,
            preset_version,
            source_policy_version,
            command_policy_version,
        )
    };
    let (Ok(original), Ok(current)) = (
        derive(original_project, original_scope, original_snapshot),
        derive(current_project, current_scope, current_snapshot),
    ) else {
        return Invalid;
    };
    if original_project != current_project {
        return IdentityChanged;
    }
    let (
        RetainedScopeSemanticsV1::SupportedV1(original),
        RetainedScopeSemanticsV1::SupportedV1(current),
    ) = (original, current)
    else {
        return Unsupported;
    };
    if !super::human_compatibility::same_nonmanaged_scope_shape(original_scope, current_scope)
        || original_snapshot.record.instance_epoch != current_snapshot.record.instance_epoch
        || original_snapshot.record.status != current_snapshot.record.status
        || original_snapshot.record.managed_deny_mask != current_snapshot.record.managed_deny_mask
    {
        return IdentityChanged;
    }
    if !super::human_compatibility::semantics_equal(&original, &current) {
        return RelevantChange;
    }
    Compatible { original, current }
}
