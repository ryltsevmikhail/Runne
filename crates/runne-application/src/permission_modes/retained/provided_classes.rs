//! Fixed mapping from a supported retained scope to managed effect classes.

use super::super::composite::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, FilesystemPermission,
    FilesystemPosture, NetworkScope,
};

/// Maps only supported broad same-user shapes in canonical class order.
pub(super) fn retained_provided_classes(scope: &CompositeEffectScope) -> Option<[bool; 6]> {
    if scope.validate().is_err()
        || !matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
        || scope.children != ChildDelegationScope::Unbounded
        || scope.budget.max_operations.is_some()
        || scope.budget.max_bytes.is_some()
        || !matches!(
            scope.network,
            NetworkScope::None | NetworkScope::BroadSameUser
        )
    {
        return None;
    }
    let permissions = &scope.filesystem.permissions;
    let has = |permission| permissions.contains(&permission);
    match scope.containment {
        ContainmentStrategy::SameUserCompositeV1 => {
            if ![
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .into_iter()
            .all(has)
            {
                return None;
            }
        }
        ContainmentStrategy::SameUserCompositeV2 => {
            if has(FilesystemPermission::Create) && !has(FilesystemPermission::Write)
                || !scope.managed_policy.supports_scope_shape(scope)
            {
                return None;
            }
        }
        ContainmentStrategy::WorkspaceBoundV1 => return None,
    }
    Some([
        has(FilesystemPermission::Read),
        has(FilesystemPermission::Create),
        has(FilesystemPermission::Write) || has(FilesystemPermission::Create),
        has(FilesystemPermission::Delete),
        true,
        scope.network == NetworkScope::BroadSameUser,
    ])
}
