use runne_application::project_trust::{
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, managed_effect_policy_digest_v2,
};
use runne_domain::id::IntegrityDigest;

use super::{
    model::{ClosedRulesManagedIdentityV2, ManagedIdentityChallengeBindingV2},
    validation,
};
use crate::store::permission_modes::{
    identity,
    model::{ManagedSnapshot, PermissionModeAuthorityContext, PermissionModeStoreError},
};

pub(in crate::store::permission_modes) fn current(
    authority: &PermissionModeAuthorityContext<'_>,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
) -> Result<ClosedRulesManagedIdentityV2, PermissionModeStoreError> {
    if authority.trust_project_id.as_bytes() != &workspace.project_id
        || managed.project_id.as_bytes() != &workspace.project_id
    {
        return Err(PermissionModeStoreError::ManagedPolicyStale);
    }
    let snapshot = authority
        .trust_lease
        .snapshot()
        .map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?;
    if snapshot.record != authority.trust_lease.record()
        || snapshot.record.instance_epoch != managed.instance_epoch
        || snapshot.record.revision != managed.revision
        || snapshot.record.status != managed.status
        || snapshot.record.managed_deny_mask != managed.deny_mask
        || workspace.project_version == 0
    {
        return Err(PermissionModeStoreError::ManagedPolicyStale);
    }
    identity_for_snapshot(
        ProjectTrustProjectId::from_bytes(workspace.project_id),
        workspace.project_version,
        snapshot,
    )
}

pub(in crate::store::permission_modes) fn identity_for_snapshot(
    project: ProjectTrustProjectId,
    project_version: u64,
    snapshot: ProjectTrustEffectPolicySnapshot,
) -> Result<ClosedRulesManagedIdentityV2, PermissionModeStoreError> {
    let canonical_digest = managed_effect_policy_digest_v2(project, &snapshot)
        .ok_or(PermissionModeStoreError::ManagedPolicyStale)?;
    let identity = ClosedRulesManagedIdentityV2 {
        project_id: *project.as_bytes(),
        project_version,
        snapshot,
        canonical_digest: IntegrityDigest::from_bytes(canonical_digest),
        challenge_binding: None,
    };
    validation::validate(&identity)?;
    Ok(identity)
}

pub(in crate::store::permission_modes) fn with_challenge(
    mut identity: ClosedRulesManagedIdentityV2,
    legacy_issued_digest: [u8; 32],
) -> ClosedRulesManagedIdentityV2 {
    let legacy_issued_digest = IntegrityDigest::from_bytes(legacy_issued_digest);
    let envelope_digest = super::digest::envelope_digest(
        *legacy_issued_digest.as_bytes(),
        *identity.canonical_digest.as_bytes(),
        identity.project_version,
    );
    identity.challenge_binding = Some(ManagedIdentityChallengeBindingV2 {
        legacy_issued_digest,
        envelope_digest,
    });
    identity
}
