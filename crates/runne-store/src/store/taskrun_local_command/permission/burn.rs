use super::{
    capture::{verify_current_selection, verify_submit_origin},
    model::{
        load_capture, now_ms, read_capture_digest, validate_area, verify_admission, verify_running,
        verify_workspace,
    },
    owner::PermissionRootFenceRequestV1,
};
use crate::store::{ManagedIdentityMetadata, PermissionModeAuthorityContext, StoreTransaction};
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
    project_trust::ProjectTrustProjectId,
};
use runne_platform::{
    local_command_linux::PermissionChildV1, process_managed_area::LinuxManagedArea,
};
use rusqlite::{TransactionBehavior, params};
use uuid::Uuid;

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
        let trust = lease.snapshot().map_err(|_| EventStoreError::Unavailable)?;
        let scope = binding.selection().scope.clone();
        let authority =
            PermissionModeAuthorityContext::new(&scope.principal_id, project, lease.as_ref(), None);
        let current = self
            .load_permission_mode_selection_with_managed_identity(
                &scope,
                &scope.principal_id,
                &authority,
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let managed = match current.identity {
            ManagedIdentityMetadata::ClosedRulesV2(value) => value,
            ManagedIdentityMetadata::LegacyRecordV1(_) => return Err(EventStoreError::CorruptData),
        };
        if current.selection != *binding.selection()
            || managed.snapshot != trust
            || managed.snapshot != binding.closed_rules_snapshot()
            || managed.canonical_digest != binding.closed_rules_digest()
            || current
                .selection
                .expires_at_unix_ms
                .is_some_and(|expiry| expiry <= now_ms())
        {
            return Err(EventStoreError::CorruptData);
        }
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
        )?;
        self.release_burned_child(
            identity,
            claimed_version,
            binding,
            &area_id,
            binding_digest,
            &root_request,
            &managed.snapshot,
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
        verify_running(&tx, identity, version)?;
        verify_submit_origin(self, &tx, binding)?;
        verify_current_selection(
            &tx,
            &binding.selection().scope,
            binding.selection(),
            ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes()),
        )?;
        if binding
            .selection()
            .expires_at_unix_ms
            .is_some_and(|expiry| expiry <= now_ms())
        {
            return Err(EventStoreError::CorruptData);
        }
        let capture = load_capture(&tx, identity, binding, false)?;
        if capture.0.as_slice() != digest.as_slice() {
            return Err(EventStoreError::CorruptData);
        }
        super::stop::ensure_not_stopped(
            &tx,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            &digest,
        )?;
        verify_admission(&tx, binding, &digest, now_ms(), false)?;
        verify_workspace(&tx, binding)?;
        let root = owner
            .acquire_root_fence(&self.runtime_authority_id, request)
            .map_err(|_| EventStoreError::CorruptData)?;
        if root.broker_root_version() != binding.admitted_root_version()
            || root.broker_root_identity() != binding.held_root_identity_digest().as_bytes()
        {
            return Err(EventStoreError::CorruptData);
        }
        let burn = *Uuid::now_v7().as_bytes();
        tx.execute(
            "INSERT INTO x2_permission_spent(taskrun_id,attempt_id,binding_digest,invocation_id,area_identity,owner_id,owner_generation,burn_id,burned_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![identity.taskrun_id.as_bytes(), identity.attempt_id.as_bytes(), digest.as_slice(),
                binding.invocation_id().as_bytes(), area.as_slice(), capture.2.as_slice(), capture.3.as_slice(),
                burn.as_slice(), now_ms().max(1)],
        ).map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET managed_area_identity=?1,state='launch_intent',updated_at=?2
             WHERE taskrun_id=?3 AND attempt_id=?4 AND fence=?5 AND state='approved'
               AND executable_digest IS NULL AND approval_id IS NULL AND managed_area_identity IS NULL",
            params![area.as_slice(), now_ms(), identity.taskrun_id.as_bytes(), identity.attempt_id.as_bytes(), identity.fence.0 as i64],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        let reserved = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='release_reserved',updated_at=?1
             WHERE taskrun_id=?2 AND attempt_id=?3 AND fence=?4 AND managed_area_identity=?5 AND state='launch_intent'",
            params![now_ms(), identity.taskrun_id.as_bytes(), identity.attempt_id.as_bytes(), identity.fence.0 as i64, area.as_slice()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if reserved != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
