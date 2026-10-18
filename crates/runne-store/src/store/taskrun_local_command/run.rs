use super::super::*;
use super::LocalCommandAttemptState;
use runne_application::ports::{EventStoreError, TaskRunAssignmentIdentity};
use runne_domain::task_run::TaskRunState;
#[cfg(target_os = "linux")]
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl StoreTransaction {
    /// Records durable cancellation intent before the caller signals the area.
    pub fn request_local_command_stop(
        &self,
        identity: &TaskRunAssignmentIdentity,
        area_identity: &[u8],
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        super::permission::require_legacy_bound_route(&tx, identity.taskrun_id)?;
        let stream = super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Cancelling {
            return Err(EventStoreError::CorruptData);
        }
        super::super::taskrun_claim::verify_cancelling_assignment(&tx, identity, stream.version)
            .map_err(|_| EventStoreError::CorruptData)?;
        let state: Option<String> = tx.query_row(
            "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4 AND managed_area_identity=?5",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity], |row| row.get(0),
        ).optional().map_err(|_| EventStoreError::CorruptData)?;
        let Some(state) = state else {
            return Err(EventStoreError::CorruptData);
        };
        if matches!(
            LocalCommandAttemptState::from_sql(&state)?,
            LocalCommandAttemptState::CancelRequested
                | LocalCommandAttemptState::Cancelled
                | LocalCommandAttemptState::Completed
        ) {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='cancel_requested',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6 AND state IN ('launch_intent','release_reserved','running')",
            params![now_millis(),identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Commits exact empty-area stop proof while retaining the area for recovery.
    #[cfg(target_os = "linux")]
    pub fn confirm_local_command_stopped(
        &self,
        identity: &TaskRunAssignmentIdentity,
        area_identity: &[u8],
        empty: VerifiedEmptyManagedArea<'_>,
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        super::permission::require_legacy_bound_route(&tx, identity.taskrun_id)?;
        verify_empty_proof(&empty, area_identity)?;
        let stream = super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        super::super::taskrun_claim::verify_cancelling_assignment(&tx, identity, stream.version)
            .map_err(|_| EventStoreError::CorruptData)?;
        let state: Option<String> = tx.query_row(
            "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4 AND managed_area_identity=?5",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity], |row| row.get(0),
        ).optional().map_err(|_| EventStoreError::CorruptData)?;
        if matches!(state.as_deref(), Some("cancelled" | "completed"))
            && stream.state == TaskRunState::Cancelling
        {
            verify_empty_proof(&empty, area_identity)?;
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='cancelled',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6 AND state='cancel_requested'",
            params![now_millis(),identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 || stream.state != TaskRunState::Cancelling {
            return Err(EventStoreError::CorruptData);
        }
        verify_empty_proof(&empty, area_identity)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Preserves an unresolved stop outcome after authority or cleanup failure.
    pub fn mark_local_command_stop_unconfirmed(
        &self,
        identity: &TaskRunAssignmentIdentity,
        area_identity: &[u8],
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        super::permission::require_legacy_bound_route(&tx, identity.taskrun_id)?;
        let state: Option<String> = tx.query_row(
            "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4 AND managed_area_identity=?5",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity], |row| row.get(0),
        ).optional().map_err(|_| EventStoreError::CorruptData)?;
        let Some(state) = state else {
            return Err(EventStoreError::CorruptData);
        };
        if state == "stop_unconfirmed" {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        if !matches!(
            state.as_str(),
            "launch_intent" | "release_reserved" | "running" | "cancel_requested"
        ) {
            return Err(EventStoreError::CorruptData);
        }
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='stop_unconfirmed',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6 AND state=?7",
            params![now_millis(),identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity,state],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Durably records exit plus prior recursive-empty proof before TaskRun completion.
    #[cfg(target_os = "linux")]
    pub fn record_local_command_exit(
        &self,
        identity: &TaskRunAssignmentIdentity,
        area_identity: &[u8],
        exit_code: i32,
        empty: VerifiedEmptyManagedArea<'_>,
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        super::permission::require_legacy_bound_route(&tx, identity.taskrun_id)?;
        verify_empty_proof(&empty, area_identity)?;
        super::super::taskrun_claim::verify_active_assignment(&tx, identity)
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Running {
            return Err(EventStoreError::CorruptData);
        }
        let row: Option<(Vec<u8>, String)> = tx.query_row(
            "SELECT node_id,state FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4 AND managed_area_identity=?5",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|_| EventStoreError::CorruptData)?;
        let Some((node, state)) = row else {
            return Err(EventStoreError::CorruptData);
        };
        if LocalCommandAttemptState::from_sql(&state)? != LocalCommandAttemptState::Running {
            return Err(EventStoreError::CorruptData);
        }
        let node_uuid =
            uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?;
        if node.as_slice() != node_uuid.as_bytes() {
            return Err(EventStoreError::CorruptData);
        }
        verify_empty_proof(&empty, area_identity)?;
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='completed',exit_code=?1,updated_at=?2 WHERE taskrun_id=?3 AND attempt_id=?4 AND node_epoch=?5 AND fence=?6 AND managed_area_identity=?7 AND state='running'",
            params![exit_code,now_millis(),identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn verify_empty_proof(
    proof: &VerifiedEmptyManagedArea<'_>,
    expected_identity: &[u8],
) -> Result<(), EventStoreError> {
    if proof.identity_bytes().as_slice() != expected_identity || proof.revalidate().is_err() {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
