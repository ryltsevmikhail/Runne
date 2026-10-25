use super::{
    model::{read_capture_digest, validate_area},
    owner::PermissionRootFenceRequestV1,
};
use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
    project_trust::ProjectTrustProjectId,
};
use runne_platform::{
    local_command_linux::PermissionChildV1, process_managed_area::LinuxManagedArea,
};
use rusqlite::TransactionBehavior;

impl StoreTransaction {
    /// Commits the one-shot burn before releasing this exact native child.
    pub fn release_local_command_permission<'area>(
        &self,
        identity: &TaskRunAssignmentIdentity,
        claimed_version: u64,
        binding: &LocalCommandPermissionBindingV1,
        area: &'area LinuxManagedArea,
        child: &mut PermissionChildV1<'area>,
    ) -> Result<(), EventStoreError> {
        if identity != binding.assignment()
            || claimed_version != binding.claim_stream_version()
            || child.original_binding() != binding
            || child.was_released()
        {
            return Err(EventStoreError::CorruptData);
        }
        let area_id = area.identity().to_bytes();
        validate_area(identity, &area_id)?;
        let project = ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes());
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or(EventStoreError::Unavailable)?;
        let lease = owner
            .acquire_effect_lease(&self.runtime_authority_id, project)
            .map_err(|_| EventStoreError::Unavailable)?;
        let scope = binding.selection().scope.clone();
        let root_request = PermissionRootFenceRequestV1::new(
            scope.workspace_id,
            binding.workspace_version(),
            binding.admitted_root_version(),
            *binding.held_root_identity_digest().as_bytes(),
        );
        let binding_digest = read_capture_digest(self, binding)?;
        self.commit_permission_burn(
            identity,
            claimed_version,
            binding,
            &area_id,
            binding_digest,
            &root_request,
            lease.as_ref(),
        )?;
        self.release_burned_child(
            identity,
            claimed_version,
            binding,
            &area_id,
            binding_digest,
            &root_request,
            lease.as_ref(),
            child,
        )?;
        Ok(())
    }

    fn commit_permission_burn(
        &self,
        identity: &TaskRunAssignmentIdentity,
        version: u64,
        binding: &LocalCommandPermissionBindingV1,
        area: &[u8; 100],
        digest: [u8; 32],
        request: &PermissionRootFenceRequestV1,
        lease: &dyn runne_application::project_trust::ProjectTrustEffectLease,
    ) -> Result<(), EventStoreError> {
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or(EventStoreError::Unavailable)?;
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        let root = owner
            .acquire_root_fence(&self.runtime_authority_id, request)
            .map_err(|_| EventStoreError::CorruptData)?;
        super::burn_guard::commit_in_tx(
            &tx,
            self,
            identity,
            version,
            binding,
            area,
            digest,
            root.as_ref(),
            lease,
        )?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
