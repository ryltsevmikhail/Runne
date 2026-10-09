use super::super::{
    LinuxCommandError, LinuxCompositeScopeAdmission, child::composite::PreparedComposite,
};
use super::{
    child::PermissionChildV1, codec, helper_protocol, lineage::LinuxPermissionOwnerV1,
    terminal::PermissionHelperChildV1,
};
use runne_application::permission_modes::ContainmentStrategy;
use std::fs::File;
use std::sync::Arc;

impl LinuxPermissionOwnerV1 {
    /// Releases only a child created by this exact registered native owner and root.
    pub fn release_child(
        &self,
        child: &mut PermissionChildV1<'_>,
        workspace: &File,
    ) -> Result<(), LinuxCommandError> {
        let observation = child.bound.observation();
        if observation.owner_id != self.owner_id
            || observation.owner_generation != self.generation
            || codec::descriptor_identity(workspace)? != observation.workspace_identity
            || child.receipt().scope_digest()
                != child
                    .bound
                    .original()
                    .scope()
                    .digest()
                    .map_err(|_| LinuxCommandError::Unverified)?
            || child.receipt().containment() != child.bound.original().scope().containment
            || child.child.was_released()
        {
            return Err(LinuxCommandError::Unverified);
        }
        child.child.release()
    }

    /// Releases only the exact consumed helper child while its Store root fence is held.
    pub fn release_helper_child(
        &self,
        child: &mut PermissionHelperChildV1<'_>,
        workspace: &File,
    ) -> Result<(), LinuxCommandError> {
        if self.owner_id != child.owner_id
            || self.generation != child.generation
            || !Arc::ptr_eq(&self.admission, &child.admission)
            || LinuxCompositeScopeAdmission::workspace_root_identity(workspace)?
                != LinuxCompositeScopeAdmission::workspace_root_identity(&child.workspace)?
            || child.area.identity().to_bytes() != child.area_identity
            || helper_protocol::helper_request_digest(&child.request)
                != child.parsed.observation.request_digest
            || !helper_protocol::helper_is_current(child.parsed.observation.expires_at_unix_ms)?
            || child.receipt.scope_digest()
                != child
                    .scope
                    .digest()
                    .map_err(|_| LinuxCommandError::Unverified)?
            || child.receipt.managed_policy_digest() != child.scope.managed_policy.policy_digest()
            || child.receipt.containment() != ContainmentStrategy::WorkspaceBoundV1
            || child.admitted_at.elapsed()
                > std::time::Duration::from_millis(child.scope.lifetime_ms)
            || child.child.was_released()
        {
            return Err(LinuxCommandError::Unverified);
        }
        self.admission
            .validate_helper_scope(&child.scope, child.parsed.observation.operation)?;
        let prepared: &PreparedComposite = &child.prepared;
        prepared.validate_workspace_bound(workspace, &child.cwd)?;
        prepared.validate_workspace_bound(&child.workspace, &child.cwd)?;
        helper_protocol::check_helper_target(&child.parsed, workspace)?;
        child.child.release()
    }
}
