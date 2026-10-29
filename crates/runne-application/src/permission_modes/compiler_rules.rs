//! Pure helpers for validating invocation evidence and applying preset rules.

use super::{
    binding::ApprovalBinding,
    composite::{
        CompositeEffectScope, CompositeScopeDigest, FilesystemPermission, FilesystemPosture,
    },
    model::PermissionMode,
    resource::{
        ObjectKind, PermissionAction, ResolutionState, ResourceFacts, Sensitivity, SizeBound,
        TargetState, WorkspaceRelation,
    },
};

pub(super) fn binding_matches(
    binding: &ApprovalBinding,
    action: PermissionAction,
    scope: &CompositeEffectScope,
    digest: CompositeScopeDigest,
) -> bool {
    binding.action == action
        && binding.principal_id == scope.permission_scope.principal_id
        && binding.composite_scope_digest == digest
        && binding.containment_version == scope.containment
        && binding.relevant_policy_digest == scope.managed_policy.policy_digest()
        && (action != PermissionAction::ProcessStart || binding.executable_digest.is_some())
}

pub(super) fn should_auto_admit(
    mode: PermissionMode,
    action: PermissionAction,
    facts: &ResourceFacts,
    scope: &CompositeEffectScope,
) -> bool {
    if scope.managed_policy.is_closed()
        && mode != PermissionMode::FullAccess
        && matches!(scope.filesystem.posture, FilesystemPosture::BroadSameUser)
        && scope.containment != super::composite::ContainmentStrategy::SameUserCompositeV2
    {
        return false;
    }
    let safe_resource = facts.workspace == WorkspaceRelation::Inside
        && facts.sensitivity == Sensitivity::Nonsensitive
        && facts.size == SizeBound::Bounded
        && facts.resolution == ResolutionState::HeldSafe;
    match mode {
        PermissionMode::AskAlways => {
            action == PermissionAction::FsRead
                && safe_resource
                && facts.target == TargetState::Existing
                && facts.object == ObjectKind::RegularFile
        }
        PermissionMode::RiskBased => match action {
            PermissionAction::FsRead => {
                safe_resource
                    && facts.target == TargetState::Existing
                    && facts.object == ObjectKind::RegularFile
            }
            PermissionAction::FsCreate => {
                safe_resource
                    && facts.target == TargetState::Absent
                    && facts.object == ObjectKind::RegularFile
                    && !facts.executable
            }
            _ => false,
        },
        PermissionMode::FullAccess => full_access_contains(action, scope),
    }
}

pub(super) fn effect_is_in_scope(
    action: PermissionAction,
    facts: &ResourceFacts,
    scope: &CompositeEffectScope,
) -> bool {
    match action {
        PermissionAction::FsRead => fs_target_is_in_scope(scope, facts, FilesystemPermission::Read),
        PermissionAction::FsCreate => {
            fs_target_is_in_scope(scope, facts, FilesystemPermission::Create)
        }
        PermissionAction::FsWrite => {
            fs_target_is_in_scope(scope, facts, FilesystemPermission::Write)
        }
        PermissionAction::FsDelete => {
            fs_target_is_in_scope(scope, facts, FilesystemPermission::Delete)
        }
        PermissionAction::NetworkConnect | PermissionAction::NetworkSend => {
            !scope.network.is_none()
        }
        PermissionAction::ProcessStart => {
            if scope.containment == super::composite::ContainmentStrategy::WorkspaceBoundV1 {
                return workspace_process_is_contained(scope, facts);
            }
            matches!(
                scope.containment,
                super::composite::ContainmentStrategy::SameUserCompositeV1
                    | super::composite::ContainmentStrategy::SameUserCompositeV2
            ) && facts.resolution == ResolutionState::HeldSafe
        }
    }
}

fn fs_target_is_in_scope(
    scope: &CompositeEffectScope,
    facts: &ResourceFacts,
    permission: FilesystemPermission,
) -> bool {
    if !fs_permitted(scope, permission) || facts.resolution != ResolutionState::HeldSafe {
        return false;
    }
    match &scope.filesystem.posture {
        FilesystemPosture::None => false,
        FilesystemPosture::BroadSameUser => true,
        FilesystemPosture::BoundedRoots(roots) => {
            facts.resolved_path.as_ref().is_some_and(|path| {
                roots
                    .iter()
                    .any(|root| super::attenuation::root_contains(root, path))
            })
        }
    }
}

fn fs_permitted(scope: &CompositeEffectScope, permission: FilesystemPermission) -> bool {
    scope.filesystem.permissions.contains(&permission)
        && !matches!(scope.filesystem.posture, FilesystemPosture::None)
        && (permission != FilesystemPermission::Create
            || scope.containment != super::composite::ContainmentStrategy::SameUserCompositeV2
            || scope
                .filesystem
                .permissions
                .contains(&FilesystemPermission::Write))
}

fn full_access_contains(action: PermissionAction, scope: &CompositeEffectScope) -> bool {
    match action {
        PermissionAction::FsRead => fs_permitted(scope, FilesystemPermission::Read),
        PermissionAction::FsCreate => fs_permitted(scope, FilesystemPermission::Create),
        PermissionAction::FsWrite => fs_permitted(scope, FilesystemPermission::Write),
        PermissionAction::FsDelete => fs_permitted(scope, FilesystemPermission::Delete),
        PermissionAction::NetworkConnect | PermissionAction::NetworkSend => {
            !scope.network.is_none()
        }
        PermissionAction::ProcessStart => {
            matches!(
                scope.containment,
                super::composite::ContainmentStrategy::SameUserCompositeV1
                    | super::composite::ContainmentStrategy::SameUserCompositeV2
            )
        }
    }
}

// One explicitly approved helper invocation may launch descendants, all under
// the same native workspace, network and managed-area containment.
fn workspace_process_is_contained(scope: &CompositeEffectScope, facts: &ResourceFacts) -> bool {
    workspace_process_scope(scope)
        && facts.workspace == WorkspaceRelation::Inside
        && fs_target_is_in_scope(scope, facts, FilesystemPermission::Read)
}

pub(super) fn workspace_process_scope(scope: &CompositeEffectScope) -> bool {
    use super::composite::{ChildDelegationScope, NetworkScope};
    scope.containment == super::composite::ContainmentStrategy::WorkspaceBoundV1
        && scope.network == NetworkScope::None
        && scope.children == ChildDelegationScope::Unbounded
        && scope.budget.max_operations == Some(1)
        && scope.budget.max_bytes.is_none()
        && matches!(&scope.filesystem.posture, FilesystemPosture::BoundedRoots(roots) if roots.len() == 1)
        && scope.filesystem.permissions
            == [
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ]
            .into_iter()
            .collect()
}
