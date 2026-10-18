use runne_application::project_trust::{
    FROZEN_POLICY_VERSION, LOCAL_COMMAND_POLICY_VERSION, ProjectTrustProjectId,
    managed_effect_policy_digest_v2,
};

use super::{digest, model::ClosedRulesManagedIdentityV2};
use crate::store::permission_modes::model::PermissionModeStoreError;

pub(super) fn validate(
    identity: &ClosedRulesManagedIdentityV2,
) -> Result<(), PermissionModeStoreError> {
    let project = ProjectTrustProjectId::from_bytes(identity.project_id);
    let snapshot = identity.snapshot;
    if identity.project_version == 0
        || i64::try_from(identity.project_version).is_err()
        || !snapshot.is_valid()
        || i64::try_from(snapshot.record.instance_epoch).is_err()
        || i64::try_from(snapshot.record.revision).is_err()
        || FROZEN_POLICY_VERSION != 2
        || LOCAL_COMMAND_POLICY_VERSION != 1
        || managed_effect_policy_digest_v2(project, &snapshot)
            .map(runne_domain::id::IntegrityDigest::from_bytes)
            != Some(identity.canonical_digest)
    {
        return Err(PermissionModeStoreError::ManagedPolicyStale);
    }
    if let Some(binding) = identity.challenge_binding
        && digest::envelope_digest(
            *binding.legacy_issued_digest.as_bytes(),
            *identity.canonical_digest.as_bytes(),
            identity.project_version,
        ) != binding.envelope_digest
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(())
}

pub(in crate::store::permission_modes) fn same_rules(
    left: &ClosedRulesManagedIdentityV2,
    right: &ClosedRulesManagedIdentityV2,
) -> bool {
    left.project_id == right.project_id
        && left.project_version == right.project_version
        && left.snapshot == right.snapshot
        && left.canonical_digest == right.canonical_digest
}
