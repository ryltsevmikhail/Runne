use super::*;
use runne_application::permission_modes::{
    ChildDelegationScope, FilesystemPermission, NetworkScope,
};
impl LinuxCompositeScopeAdmission {
    pub(in crate::local_command_linux) fn validate_helper_scope(
        &self,
        scope: &CompositeEffectScope,
        operation: PermissionHelperOperationV1,
    ) -> Result<(), LinuxCommandError> {
        let roots = match &scope.filesystem.posture {
            FilesystemPosture::BoundedRoots(roots) => roots,
            _ => return Err(LinuxCommandError::CompositePolicyUnenforceable),
        };
        let expected_permissions = operation.permissions().iter().copied().collect();
        if scope.validate().is_err()
            || scope.protected_control_plane_policy_digest != self.protected_policy_digest
            || scope.managed_policy.is_unrestricted()
            || !scope.managed_policy.is_closed()
            || scope.containment != ContainmentStrategy::WorkspaceBoundV1
            || scope.network != NetworkScope::None
            || scope.children
                != if operation == PermissionHelperOperationV1::Command {
                    ChildDelegationScope::Unbounded
                } else {
                    ChildDelegationScope::None
                }
            || roots.len() != 1
            || roots
                .iter()
                .next()
                .is_none_or(|root| !root.components.is_empty())
            || scope.filesystem.permissions != expected_permissions
            || scope.budget.max_operations != Some(1)
            || if operation == PermissionHelperOperationV1::Command {
                scope.budget.max_bytes.is_some()
            } else {
                scope.budget.max_bytes.is_none_or(|bytes| bytes > 8192)
            }
            || scope.lifetime_ms == 0
            || scope.lifetime_ms > 120_000
        {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        Ok(())
    }
}
pub(super) fn helper_operation_from_scope(
    scope: &CompositeEffectScope,
) -> Option<PermissionHelperOperationV1> {
    if scope.children == ChildDelegationScope::Unbounded
        && scope.filesystem.permissions
            == PermissionHelperOperationV1::Command
                .permissions()
                .iter()
                .copied()
                .collect()
    {
        return Some(PermissionHelperOperationV1::Command);
    }
    if scope.filesystem.permissions
        == PermissionHelperOperationV1::Replace
            .permissions()
            .iter()
            .copied()
            .collect()
    {
        return Some(PermissionHelperOperationV1::Replace);
    }
    if scope.filesystem.permissions == [FilesystemPermission::Read].into_iter().collect() {
        Some(PermissionHelperOperationV1::Read)
    } else if scope.filesystem.permissions
        == [
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
        ]
        .into_iter()
        .collect()
    {
        Some(PermissionHelperOperationV1::CreateNew)
    } else {
        None
    }
}
