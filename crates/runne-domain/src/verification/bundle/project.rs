use super::constraints::{ensure, snapshot};
use super::*;

/// Compare caller-supplied descriptions, not actual current state or authenticity.
/// Always structurally validates the bundle first; never resolves authority.
pub fn project_declared_snapshot(
    b: &BundleMetadata,
    comparison: Option<&DeclaredSnapshot>,
) -> Result<BundleProjection, BundleError> {
    let report = validate_structure(b)?;
    if let Some(s) = comparison {
        snapshot(s, 0)?;
    }
    let declared_snapshot_binding = match (&b.checked_snapshot, comparison) {
        (Some(checked), Some(other)) => {
            ensure(
                checked.taskrun_id == other.taskrun_id && checked.plan_id == other.plan_id,
                BundleErrorCode::ComparisonScopeMismatch,
                0,
            )?;
            let mut changed = vec![];
            for (differs, axis) in [
                (
                    checked.task_revision != other.task_revision,
                    BindingAxis::TaskRevision,
                ),
                (
                    checked.plan_revision != other.plan_revision,
                    BindingAxis::PlanRevision,
                ),
                (
                    checked.stream_head != other.stream_head,
                    BindingAxis::StreamHead,
                ),
                (
                    checked.source_snapshot_digest != other.source_snapshot_digest,
                    BindingAxis::SourceSnapshot,
                ),
                (
                    checked.environment != other.environment,
                    BindingAxis::Environment,
                ),
                (
                    checked.required_artifacts != other.required_artifacts,
                    BindingAxis::RequiredArtifacts,
                ),
            ] {
                if differs {
                    changed.push(axis);
                }
            }
            if changed.is_empty() {
                DeclaredSnapshotBinding::MatchesDeclaredSnapshot
            } else {
                DeclaredSnapshotBinding::StaleAgainstDeclaredSnapshot { changed }
            }
        }
        _ => {
            let mut missing = vec![];
            if b.checked_snapshot.is_none() {
                missing.push(MissingComponent::CheckedSnapshot);
            }
            if comparison.is_none() {
                missing.push(MissingComponent::ComparisonSnapshot);
            }
            DeclaredSnapshotBinding::Unknown { missing }
        }
    };
    Ok(BundleProjection {
        historical_checks: report.historical_checks,
        declared_snapshot_binding,
        authority_resolution: AuthorityResolution::NotPerformed,
        current_applicability: CurrentApplicability::UnknownWithoutE2,
    })
}
