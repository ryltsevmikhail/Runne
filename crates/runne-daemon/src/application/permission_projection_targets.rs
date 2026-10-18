//! Selection-target gating for the permission projection: the closed-rules
//! identity fence shared by the status and worker observations.

use runne_application::permission_modes::{ModeSelection, NotReadyReason};
use runne_store::store::{
    ClosedRulesManagedIdentityV2, ManagedIdentityMetadata, PermissionModeSelectionManagedIdentity,
};

use super::permission_projection::ProjectionTarget;

#[cfg(target_os = "linux")]
pub(super) fn closed_identity(
    current: &PermissionModeSelectionManagedIdentity,
) -> Result<&ClosedRulesManagedIdentityV2, NotReadyReason> {
    match &current.identity {
        ManagedIdentityMetadata::ClosedRulesV2(value) => Ok(value),
        ManagedIdentityMetadata::LegacyRecordV1(_) => {
            Err(NotReadyReason::CompositePolicyUnenforceable)
        }
    }
}

pub(super) fn workspace_binding_matches(
    version: u64,
    open: bool,
    project_id: [u8; 16],
    expected: (u64, [u8; 16]),
) -> bool {
    open && version == expected.0 && project_id == expected.1
}

#[cfg(target_os = "linux")]
pub(crate) fn selected_target(
    target: &ProjectionTarget,
    current: &PermissionModeSelectionManagedIdentity,
    managed: &ClosedRulesManagedIdentityV2,
) -> Result<ModeSelection, NotReadyReason> {
    match target {
        ProjectionTarget::Current {
            selection,
            managed_policy_version,
        } if selection == &current.selection
            && (*managed_policy_version == managed.snapshot.record.revision
                || selection.authorization_revision == 0) =>
        {
            Ok(current.selection.clone())
        }
        ProjectionTarget::Candidate {
            selection,
            expected_revision,
            managed_policy_version,
            managed_policy_digest,
        } if current.selection.authorization_revision == *expected_revision
            && selection.scope == current.selection.scope
            && selection.authorization_revision == expected_revision.saturating_add(1)
            && *managed_policy_version == managed.snapshot.record.revision
            && *managed_policy_digest == managed.canonical_digest =>
        {
            Ok(selection.clone())
        }
        _ => Err(NotReadyReason::NativeContainment),
    }
}
