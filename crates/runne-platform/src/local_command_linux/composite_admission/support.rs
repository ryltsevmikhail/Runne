use runne_application::permission_modes::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, FilesystemPermission,
    FilesystemPosture, IntegrityDigest, NetworkScope,
};
use rustix::fs::fstat;
use sha2::{Digest, Sha256};
use std::fs::File;

use crate::local_command_linux::LinuxCommandError;

pub(super) const MAX_SCOPE_LIFETIME_MS: u64 = 3_600_000;

pub(super) fn validate_scope(
    scope: &CompositeEffectScope,
    protected: IntegrityDigest,
) -> Result<(), ()> {
    scope.validate().map_err(|_| ())?;
    let broad = scope.containment == ContainmentStrategy::SameUserCompositeV1;
    if scope.protected_control_plane_policy_digest != protected
        || !scope.managed_policy.is_unrestricted()
        || (broad && scope.children != ChildDelegationScope::Unbounded)
        || (!broad && scope.children != ChildDelegationScope::None)
        || (broad && scope.budget.max_bytes.is_some())
        || (!broad && (scope.budget.max_operations != Some(1) || scope.budget.max_bytes.is_none()))
        || scope.lifetime_ms == 0
        || scope.lifetime_ms > MAX_SCOPE_LIFETIME_MS
        || scope.filesystem.permissions.is_empty()
        || (broad
            && ![
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .iter()
            .all(|permission| scope.filesystem.permissions.contains(permission)))
    {
        return Err(());
    }
    match (&scope.containment, &scope.filesystem.posture, scope.network) {
        (
            ContainmentStrategy::SameUserCompositeV1,
            FilesystemPosture::BroadSameUser,
            NetworkScope::BroadSameUser | NetworkScope::None,
        ) => Ok(()),
        (
            ContainmentStrategy::WorkspaceBoundV1,
            FilesystemPosture::BoundedRoots(roots),
            NetworkScope::None,
        ) if roots.len() == 1
            && roots
                .iter()
                .next()
                .is_some_and(|root| root.components.is_empty()) =>
        {
            Ok(())
        }
        _ => Err(()),
    }
}

pub(super) fn workspace_identity(workspace: &File) -> Result<IntegrityDigest, LinuxCommandError> {
    let stat = fstat(workspace).map_err(|_| LinuxCommandError::Invalid)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(LinuxCommandError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(stat.st_dev.to_be_bytes());
    hash.update(stat.st_ino.to_be_bytes());
    Ok(IntegrityDigest::from_bytes(hash.finalize().into()))
}

pub(super) fn random_handle() -> Result<IntegrityDigest, LinuxCommandError> {
    loop {
        let mut bytes = [0u8; 32];
        let count = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if count != bytes.len() as isize {
            return Err(LinuxCommandError::Unavailable);
        }
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(IntegrityDigest::from_bytes(bytes));
        }
    }
}
