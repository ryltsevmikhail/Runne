use super::{
    capture::verify_submit_origin,
    model::{
        load_capture, now_ms, validate_area, verify_admission, verify_running, verify_workspace,
    },
    owner::PermissionRootFenceGuardV1,
};
use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
    project_trust::ProjectTrustEffectLease,
};
use rusqlite::{Transaction, params};
use uuid::Uuid;

pub(super) fn commit_in_tx(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    version: u64,
    binding: &LocalCommandPermissionBindingV1,
    area: &[u8; 100],
    digest: [u8; 32],
    root: &dyn PermissionRootFenceGuardV1,
    lease: &dyn ProjectTrustEffectLease,
) -> Result<(), EventStoreError> {
    validate_area(identity, area)?;
    verify_running(tx, identity, version)?;
    verify_submit_origin(store, tx, binding)?;
    super::retained_policy::require_current(tx, store, binding, lease)?;
    let capture = load_capture(tx, identity, binding, false)?;
    if capture.0.as_slice() != digest.as_slice() {
        return Err(EventStoreError::CorruptData);
    }
    super::stop::ensure_not_stopped(
        tx,
        identity.taskrun_id.as_bytes(),
        identity.attempt_id.as_bytes(),
        &digest,
    )?;
    verify_admission(tx, binding, &digest, now_ms(), false)?;
    verify_workspace(tx, binding)?;
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
    Ok(())
}
