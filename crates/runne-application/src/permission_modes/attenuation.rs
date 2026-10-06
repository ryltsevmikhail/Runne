//! Component-wise child composite-scope attenuation.

use super::composite::{
    ChildDelegationScope, CompositeEffectScope, ContainmentStrategy, FilesystemPosture,
    FilesystemRoot, NetworkScope,
};

impl CompositeEffectScope {
    /// Whether this scope cannot add rights, roots, budget, or lifetime to `parent`.
    ///
    /// The initial contract requires equal authority, principal, workspace,
    /// managed-policy snapshot, and protected-control-plane policy. A future
    /// cross-workspace child requires a separate verified delegation contract.
    pub fn is_attenuated_from(&self, parent: &Self) -> bool {
        self.validate().is_ok()
            && parent.validate().is_ok()
            && self.permission_scope == parent.permission_scope
            && self.protected_control_plane_policy_digest
                == parent.protected_control_plane_policy_digest
            && self.managed_policy == parent.managed_policy
            && self
                .filesystem
                .permissions
                .is_subset(&parent.filesystem.permissions)
            && filesystem_is_attenuated(&self.filesystem.posture, &parent.filesystem.posture)
            && network_is_attenuated(self.network, parent.network)
            && child_scope_is_attenuated(self.children, parent.children)
            && budget_is_attenuated(self.budget.max_operations, parent.budget.max_operations)
            && budget_is_attenuated(self.budget.max_bytes, parent.budget.max_bytes)
            && self.lifetime_ms <= parent.lifetime_ms
            && containment_is_attenuated(self.containment, parent.containment)
    }
}

pub(super) fn root_contains(parent: &FilesystemRoot, child: &FilesystemRoot) -> bool {
    parent.root_identity == child.root_identity
        && child.components.len() >= parent.components.len()
        && child.components[..parent.components.len()] == parent.components[..]
}

fn filesystem_is_attenuated(child: &FilesystemPosture, parent: &FilesystemPosture) -> bool {
    match (child, parent) {
        (FilesystemPosture::None, _) => true,
        (FilesystemPosture::BoundedRoots(children), FilesystemPosture::BoundedRoots(parents)) => {
            children
                .iter()
                .all(|child| parents.iter().any(|parent| root_contains(parent, child)))
        }
        (FilesystemPosture::BoundedRoots(_), FilesystemPosture::BroadSameUser) => true,
        (FilesystemPosture::BroadSameUser, FilesystemPosture::BroadSameUser) => true,
        _ => false,
    }
}

fn network_is_attenuated(child: NetworkScope, parent: NetworkScope) -> bool {
    match (child, parent) {
        (NetworkScope::None, _) => true,
        (
            NetworkScope::Brokered { policy_digest: a },
            NetworkScope::Brokered { policy_digest: b },
        ) => a == b,
        (NetworkScope::BroadSameUser, NetworkScope::BroadSameUser) => true,
        _ => false,
    }
}

fn child_scope_is_attenuated(child: ChildDelegationScope, parent: ChildDelegationScope) -> bool {
    match (child, parent) {
        (ChildDelegationScope::None, _) => true,
        (ChildDelegationScope::MaxDepth(_), ChildDelegationScope::Unbounded) => true,
        (ChildDelegationScope::MaxDepth(child), ChildDelegationScope::MaxDepth(parent)) => {
            child <= parent
        }
        (ChildDelegationScope::Unbounded, ChildDelegationScope::Unbounded) => true,
        _ => false,
    }
}

fn budget_is_attenuated(child: Option<u64>, parent: Option<u64>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(child), Some(parent)) => child <= parent,
    }
}

fn containment_is_attenuated(child: ContainmentStrategy, parent: ContainmentStrategy) -> bool {
    child == parent
        || matches!(
            (child, parent),
            (
                ContainmentStrategy::WorkspaceBoundV1,
                ContainmentStrategy::SameUserCompositeV1
            )
        )
}
