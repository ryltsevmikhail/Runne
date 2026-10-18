//! Canonical managed-effect policy digest shared by the compiler and T1 store.

use sha2::Sha256;

use super::{
    FROZEN_POLICY_VERSION, LOCAL_COMMAND_POLICY_VERSION, ManagedEffectClass,
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, ProjectTrustStatus,
};
use sha2::Digest;

/// Computes the canonical V2 digest for a project and its T1 policy snapshot.
///
/// Returns `None` for an invalid record, unsupported rule version, or unsupported
/// status/mask shape. Rule bytes always follow [`ManagedEffectClass::ALL`].
pub fn managed_effect_policy_digest_v2(
    project: ProjectTrustProjectId,
    snapshot: &ProjectTrustEffectPolicySnapshot,
) -> Option<[u8; 32]> {
    if !snapshot.is_valid() {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(b"runne.managed-effect-policy-digest.v2\0");
    digest.update(project.as_bytes());
    digest.update([match snapshot.record.status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    }]);
    digest.update(snapshot.record.managed_deny_mask.to_be_bytes());
    digest.update(snapshot.record.instance_epoch.to_be_bytes());
    digest.update(snapshot.record.revision.to_be_bytes());
    digest.update(snapshot.policy.version.to_be_bytes());
    for (class, decision) in ManagedEffectClass::ALL
        .into_iter()
        .zip(snapshot.policy.decisions())
    {
        digest.update([class.tag(), decision.tag()]);
    }
    digest.update(FROZEN_POLICY_VERSION.to_be_bytes());
    digest.update(LOCAL_COMMAND_POLICY_VERSION.to_be_bytes());
    Some(digest.finalize().into())
}
