use runne_application::project_trust::{ManagedEffectDecision, ProjectTrustStatus};
use runne_domain::id::IntegrityDigest;

use crate::store::permission_modes::model::PermissionModeStoreError;

pub(super) fn status_tag(status: ProjectTrustStatus) -> i64 {
    match status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    }
}

pub(super) fn status_from_tag(tag: i64) -> Result<ProjectTrustStatus, PermissionModeStoreError> {
    match tag {
        1 => Ok(ProjectTrustStatus::Untrusted),
        2 => Ok(ProjectTrustStatus::Trusted),
        3 => Ok(ProjectTrustStatus::Managed),
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}

pub(super) fn decision_tag(decision: ManagedEffectDecision) -> i64 {
    i64::from(decision.tag())
}

pub(super) fn decision_from_tag(
    tag: i64,
) -> Result<ManagedEffectDecision, PermissionModeStoreError> {
    let code = u8::try_from(tag)
        .ok()
        .and_then(|value| value.checked_sub(1))
        .ok_or(PermissionModeStoreError::CorruptData)?;
    ManagedEffectDecision::from_code(code).ok_or(PermissionModeStoreError::CorruptData)
}

pub(super) fn digest(bytes: Vec<u8>) -> Result<IntegrityDigest, PermissionModeStoreError> {
    Ok(IntegrityDigest::from_bytes(
        bytes
            .try_into()
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
    ))
}
