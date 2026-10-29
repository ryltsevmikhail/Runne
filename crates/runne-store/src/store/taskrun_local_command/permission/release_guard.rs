use super::{
    capture::verify_submit_origin,
    model::{
        load_capture, now_ms, observation_matches, verify_admission, verify_running,
        verify_workspace,
    },
    owner::PermissionRootFenceGuardV1,
};
use crate::store::StoreTransaction;
use runne_application::project_trust::ProjectTrustEffectLease;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
};
use runne_platform::local_command_linux::PermissionTargetObservationV1;
use rusqlite::{OptionalExtension, Transaction, params};

type SpentPermissionProofRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

// Data copied only from an actual prepared target or native child observation.
pub(super) struct ReleaseObservation(PermissionTargetObservationV1);
impl ReleaseObservation {
    pub(super) fn from_prepared(observed: PermissionTargetObservationV1) -> Self {
        Self(observed)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Distinct authenticated proof components remain explicit at the release boundary"
)]
pub(super) fn with_release_preconditions(
    tx: &Transaction<'_>,
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    version: u64,
    binding: &LocalCommandPermissionBindingV1,
    area: &[u8; 100],
    digest: [u8; 32],
    lease: &dyn ProjectTrustEffectLease,
    root: &dyn PermissionRootFenceGuardV1,
    observed: &ReleaseObservation,
    go: impl FnOnce() -> Result<(), EventStoreError>,
) -> Result<(), EventStoreError> {
    verify_running(tx, identity, version)?;
    super::retained_policy::require_current(tx, store, binding, lease)?;
    verify_submit_origin(store, tx, binding)?;
    let capture = load_capture(tx, identity, binding, false)?;
    super::stop::ensure_not_stopped(
        tx,
        identity.taskrun_id.as_bytes(),
        identity.attempt_id.as_bytes(),
        &digest,
    )?;
    verify_admission(tx, binding, &digest, now_ms(), false)?;
    verify_workspace(tx, binding)?;
    if observed.0.owner_id().as_slice() != capture.2.as_slice()
        || observed.0.owner_generation().to_be_bytes().as_slice() != capture.3.as_slice()
        || !observation_matches(binding, observed.0)
        || capture.0.as_slice() != digest.as_slice()
    {
        return Err(EventStoreError::CorruptData);
    }
    let row: Option<(Vec<u8>, String)> = tx
        .query_row(
            "SELECT managed_area_identity,state FROM taskrun_local_command_attempts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes(),
                identity.fence.0 as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if !row.is_some_and(|(saved, state)| saved.as_slice() == area && state == "release_reserved") {
        return Err(EventStoreError::CorruptData);
    }
    let spent: Option<SpentPermissionProofRow> = tx
        .query_row(
            "SELECT binding_digest,invocation_id,area_identity,owner_id,owner_generation
                 FROM x2_permission_spent WHERE taskrun_id=?1 AND attempt_id=?2",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if !spent.is_some_and(
        |(saved_digest, invocation, saved_area, owner_id, generation)| {
            saved_digest.as_slice() == digest.as_slice()
                && invocation.as_slice() == binding.invocation_id().as_bytes()
                && saved_area.as_slice() == area
                && owner_id.as_slice() == capture.2.as_slice()
                && generation.as_slice() == capture.3.as_slice()
        },
    ) {
        return Err(EventStoreError::CorruptData);
    }
    if root.broker_root_version() != binding.admitted_root_version()
        || root.broker_root_identity() != binding.held_root_identity_digest().as_bytes()
    {
        return Err(EventStoreError::CorruptData);
    }
    go()?;
    let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='running',updated_at=?1
             WHERE taskrun_id=?2 AND attempt_id=?3 AND fence=?4 AND managed_area_identity=?5 AND state='release_reserved'",
            params![now_ms(), identity.taskrun_id.as_bytes(), identity.attempt_id.as_bytes(), identity.fence.0 as i64, area.as_slice()],
        ).map_err(|_| EventStoreError::CorruptData)?;
    if changed != 1 {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}
