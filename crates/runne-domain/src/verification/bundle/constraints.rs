//! Bounded structural primitives; never resolve referenced content.
use super::*;
use crate::id::validate_uuid_v7_bytes;
use crate::reference::ResultRef;

pub(super) fn ensure(ok: bool, code: BundleErrorCode, ordinal: usize) -> Result<(), BundleError> {
    if ok {
        Ok(())
    } else {
        Err(BundleError { code, ordinal })
    }
}
pub(super) fn identity(bytes: &[u8; 16], ordinal: usize) -> Result<(), BundleError> {
    ensure(
        validate_uuid_v7_bytes(bytes).is_ok(),
        BundleErrorCode::InvalidIdentity,
        ordinal,
    )
}
pub(super) fn text(s: &str, ordinal: usize) -> Result<(), BundleError> {
    ensure(
        !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control),
        BundleErrorCode::InvalidString,
        ordinal,
    )
}
pub(super) fn result(r: &ResultRef, ordinal: usize) -> Result<(), BundleError> {
    identity(r.result_id().as_bytes(), ordinal)
}
pub(super) fn order<T: Ord>(
    keys: impl Iterator<Item = T>,
    code: BundleErrorCode,
) -> Result<(), BundleError> {
    let mut last = None;
    for (i, key) in keys.enumerate() {
        ensure(last.as_ref().is_none_or(|p| p < &key), code, i)?;
        last = Some(key);
    }
    Ok(())
}
pub(super) fn snapshot_bound(s: &DeclaredSnapshot, ordinal: usize) -> Result<(), BundleError> {
    ensure(
        s.required_artifacts.len() <= 64,
        BundleErrorCode::TooManyArtifacts,
        ordinal,
    )
}
/// All collection sizes are inspected before any nested payload/identity traversal.
pub(super) fn bounds(b: &BundleMetadata) -> Result<(), BundleError> {
    ensure(b.checks.len() <= 32, BundleErrorCode::TooManyChecks, 0)?;
    ensure(
        b.tool_returns.len() <= 64,
        BundleErrorCode::TooManyToolReturns,
        0,
    )?;
    ensure(b.effects.len() <= 64, BundleErrorCode::TooManyEffects, 0)?;
    if let Some(s) = &b.checked_snapshot {
        snapshot_bound(s, 0)?;
    }
    for (i, c) in b.checks.iter().enumerate() {
        ensure(
            c.evidence.len() <= 16,
            BundleErrorCode::TooManyEvidenceRefs,
            i,
        )?;
        if let Some(s) = &c.binding {
            snapshot_bound(s, i)?;
        }
    }
    Ok(())
}
pub(super) fn snapshot(s: &DeclaredSnapshot, ordinal: usize) -> Result<(), BundleError> {
    snapshot_bound(s, ordinal)?;
    identity(s.taskrun_id.as_bytes(), ordinal)?;
    identity(s.plan_id.as_bytes(), ordinal)?;
    result(&s.environment.result, ordinal)?;
    order(
        s.required_artifacts.iter().map(|a| a.slot),
        BundleErrorCode::ArtifactOrder,
    )?;
    for a in &s.required_artifacts {
        result(&a.artifact.result, ordinal)?;
    }
    Ok(())
}
