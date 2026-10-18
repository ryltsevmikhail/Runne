use super::super::support::MAX_SCOPE_LIFETIME_MS;
use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, EffectBudget,
    FilesystemPermission, FilesystemPosture, IntegrityDigest, NativeAdmissionError,
    NativeScopeAdmissionPort, NetworkScope, PermissionMode,
};
use sha2::{Digest, Sha256};

pub(super) fn admit_full_access(
    owner: &super::LinuxCompositeScopeAdmission,
    original: &CompositeEffectScope,
    canonical: &CompositeEffectScope,
) -> Result<IntegrityDigest, NativeAdmissionError> {
    let original_digest = original
        .digest()
        .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
    let canonical_digest = canonical
        .digest()
        .map_err(|_| NativeAdmissionError::CompositePolicyUnenforceable)?;
    let readiness = NativeScopeAdmissionPort::admit_mode_readiness(
        owner,
        PermissionMode::FullAccess,
        canonical,
    )?;
    readiness_handle(
        original_digest.as_bytes(),
        canonical_digest.as_bytes(),
        readiness,
    )
}

pub(super) fn translate_full_access_scope(
    scope: &CompositeEffectScope,
    owner_legacy_digest: IntegrityDigest,
    owner_v2_broad_digest: IntegrityDigest,
) -> Option<CompositeEffectScope> {
    let expected_permissions = [
        FilesystemPermission::Read,
        FilesystemPermission::Create,
        FilesystemPermission::Write,
        FilesystemPermission::Delete,
    ]
    .into_iter()
    .collect();
    if scope.validate().is_err()
        || !scope.managed_policy.is_closed()
        || scope.containment != ContainmentStrategy::SameUserCompositeV1
        || scope.filesystem.posture != FilesystemPosture::BroadSameUser
        || scope.filesystem.permissions != expected_permissions
        || scope.network != NetworkScope::BroadSameUser
        || scope.children != ChildDelegationScope::Unbounded
        || scope.budget
            != (EffectBudget {
                max_operations: None,
                max_bytes: None,
            })
        || scope.lifetime_ms > MAX_SCOPE_LIFETIME_MS
        || scope.protected_control_plane_policy_digest != owner_legacy_digest
    {
        return None;
    }
    let mut translated = scope.clone();
    translated.protected_control_plane_policy_digest = owner_v2_broad_digest;
    Some(translated)
}

pub(super) fn readiness_handle(
    original_scope: &[u8; 32],
    canonical_scope: &[u8; 32],
    generic_readiness: IntegrityDigest,
) -> Result<IntegrityDigest, NativeAdmissionError> {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:linux-helper-full-access-readiness:v1\0");
    hash.update(original_scope);
    hash.update(canonical_scope);
    hash.update(generic_readiness.as_bytes());
    let handle = IntegrityDigest::from_bytes(hash.finalize().into());
    if handle.as_bytes().iter().all(|byte| *byte == 0) {
        Err(NativeAdmissionError::EnforcementUnavailable)
    } else {
        Ok(handle)
    }
}

#[cfg(test)]
#[path = "helper_readiness_tests.rs"]
mod tests;
