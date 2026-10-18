use super::stop;
use super::{
    model::{load_capture, now_ms},
    stop::read_binding,
};
use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
};
use runne_domain::task_run::TaskRunState;
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl StoreTransaction {
    /// Durably records the factual leader exit of a released V68 command
    /// before its workflow terminal commit (legacy parity: run.rs
    /// `record_local_command_exit`). No stop may exist yet and the stream
    /// must still be Running: a racing cancellation keeps its own stop-path
    /// settlement instead of this factual record.
    #[cfg(target_os = "linux")]
    pub fn record_local_command_permission_exit(
        &self,
        identity: &TaskRunAssignmentIdentity,
        binding: &LocalCommandPermissionBindingV1,
        area_identity: &[u8],
        exit_code: i32,
        empty: VerifiedEmptyManagedArea<'_>,
    ) -> Result<(), EventStoreError> {
        if identity != binding.assignment() || !(0..=255).contains(&exit_code) {
            return Err(EventStoreError::CorruptData);
        }
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        let (digest, _) = read_binding(&tx, identity, binding)?;
        load_capture(&tx, identity, binding, false)?;
        if stop::stop_reason(
            &tx,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            &digest,
        )?
        .is_some()
        {
            return Err(EventStoreError::CorruptData);
        }
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Running {
            return Err(EventStoreError::CorruptData);
        }
        crate::store::taskrun_claim::verify_active_assignment(&tx, identity)
            .map_err(|_| EventStoreError::CorruptData)?;
        let row: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT managed_area_identity,state FROM taskrun_local_command_attempts
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4",
                params![
                    identity.taskrun_id.as_bytes(),
                    identity.attempt_id.as_bytes(),
                    identity.node_epoch as i64,
                    identity.fence.0 as i64
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?;
        if !row.is_some_and(|(area, state)| state == "running" && area.as_slice() == area_identity)
        {
            return Err(EventStoreError::CorruptData);
        }
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE taskrun_local_command_attempts SET state='completed',exit_code=?1,updated_at=?2
                 WHERE taskrun_id=?3 AND attempt_id=?4 AND node_epoch=?5 AND fence=?6
                   AND managed_area_identity=?7 AND state='running' AND exit_code IS NULL",
                params![
                    exit_code,
                    now_ms(),
                    identity.taskrun_id.as_bytes(),
                    identity.attempt_id.as_bytes(),
                    identity.node_epoch as i64,
                    identity.fence.0 as i64,
                    area_identity
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
