use super::super::*;
use super::LocalCommandAttemptState;
use runne_application::ports::{
    EventStoreError, ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence,
};
use runne_domain::id::{AttemptId, TaskRunId};
use runne_domain::task_run::TaskRunState;
use rusqlite::{TransactionBehavior, params};
#[cfg(target_os = "linux")]
mod cancel_complete;
mod cancel_settled;
mod cancel_support;
#[cfg(target_os = "linux")]
mod confirm;
mod helpers;
#[cfg(target_os = "linux")]
mod outcome_unknown;
#[cfg(target_os = "linux")]
mod outcome_unknown_replay;
mod stop_evidence;
pub use stop_evidence::LocalCommandCancellationStopEvidence;
mod terminal_cleanup;
#[cfg(target_os = "linux")]
pub(super) use helpers::verify_recovery_owner;
use helpers::{fixed_id, now_millis, read_exact_state};

/// Durable effect identity for startup reconciliation; this never authorizes GO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCommandRecoveryCandidate {
    pub identity: TaskRunAssignmentIdentity,
    pub area_identity: Vec<u8>,
    pub state: LocalCommandAttemptState,
    pub exit_code: Option<i32>,
}

impl StoreTransaction {
    /// Lists bounded attempts whose durable state may correspond to a process.
    pub fn scan_local_command_recovery(
        &self,
        after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<Vec<LocalCommandRecoveryCandidate>, EventStoreError> {
        if !(1..=128).contains(&limit) {
            return Err(EventStoreError::Unavailable);
        }
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT taskrun_id,attempt_id,node_id,node_epoch,fence,managed_area_identity,state,exit_code
                 FROM taskrun_local_command_attempts
                 WHERE state IN ('launch_intent','release_reserved','running','cancel_requested','completed','cancelled','stop_unconfirmed','outcome_unknown')
                   AND (state='outcome_unknown' OR NOT EXISTS (
                     SELECT 1 FROM taskrun_terminal_settlement_receipts settled
                     JOIN taskrun_assignment_occupations released
                       ON released.taskrun_id=settled.taskrun_id AND released.fence=settled.fence
                     JOIN events terminal
                       ON terminal.event_id=settled.terminal_event_id
                     WHERE settled.taskrun_id=taskrun_local_command_attempts.taskrun_id
                       AND settled.fence=taskrun_local_command_attempts.fence
                       AND settled.attempt_id=taskrun_local_command_attempts.attempt_id
                       AND settled.node_id=taskrun_local_command_attempts.node_id
                       AND settled.node_epoch=taskrun_local_command_attempts.node_epoch
                       AND released.attempt_id=taskrun_local_command_attempts.attempt_id
                       AND released.node_id=taskrun_local_command_attempts.node_id
                       AND released.node_epoch=taskrun_local_command_attempts.node_epoch
                       AND released.state='released'
                       AND released.release_event_id=settled.terminal_event_id
                       AND terminal.aggregate_type=1
                       AND terminal.aggregate_id=settled.taskrun_id
                       AND terminal.sequence=settled.terminal_version
                   ))
                   AND (?1 IS NULL OR taskrun_id>?1) ORDER BY taskrun_id LIMIT ?2",
            )
            .map_err(|_| EventStoreError::Unavailable)?;
        let rows = statement
            .query_map(
                rusqlite::params![after.map(|id| id.as_bytes().to_vec()), limit as i64],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<i32>>(7)?,
                    ))
                },
            )
            .map_err(|_| EventStoreError::Unavailable)?;
        rows.map(|row| {
            let (task, attempt, node, epoch, fence, area, state, exit_code) =
                row.map_err(|_| EventStoreError::CorruptData)?;
            let taskrun_id = fixed_id::<16>(&task)?;
            let attempt_id = fixed_id::<16>(&attempt)?;
            let node = fixed_id::<16>(&node)?;
            if epoch <= 0 || fence <= 0 || area.len() != 100 {
                return Err(EventStoreError::CorruptData);
            }
            let identity = TaskRunAssignmentIdentity {
                taskrun_id: TaskRunId::from_bytes(taskrun_id),
                attempt_id: AttemptId::from_bytes(attempt_id),
                node_id: runne_application::ports::ExecutionNodeId(
                    uuid::Uuid::from_bytes(node).to_string(),
                ),
                node_epoch: u64::try_from(epoch).map_err(|_| EventStoreError::CorruptData)?,
                fence: TaskRunFence(
                    u64::try_from(fence).map_err(|_| EventStoreError::CorruptData)?,
                ),
            };
            Ok(LocalCommandRecoveryCandidate {
                identity,
                area_identity: area,
                state: LocalCommandAttemptState::from_sql(&state)?,
                exit_code,
            })
        })
        .collect()
    }

    /// Confirms this daemon's current epoch owns the exact retained attempt.
    #[cfg(target_os = "linux")]
    pub fn authorize_local_command_recovery(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Fences a retained local effect after restart under the current node epoch.
    #[cfg(target_os = "linux")]
    pub fn request_local_command_stop_recovery(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        let stream = super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            candidate.identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Cancelling {
            return Err(EventStoreError::CorruptData);
        }
        let state = read_exact_state(&tx, candidate)?;
        if matches!(
            state,
            LocalCommandAttemptState::CancelRequested | LocalCommandAttemptState::Cancelled
        ) {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        if matches!(
            state,
            LocalCommandAttemptState::StopUnconfirmed | LocalCommandAttemptState::OutcomeUnknown
        ) {
            // These states are already durable unresolved effects. The TaskRun's
            // Cancelling event is the durable signal barrier; V51 intentionally
            // has no transition back to cancel_requested.
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        if !matches!(
            state,
            LocalCommandAttemptState::LaunchIntent
                | LocalCommandAttemptState::ReleaseReserved
                | LocalCommandAttemptState::Running
        ) {
            return Err(EventStoreError::CorruptData);
        }
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='cancel_requested',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6 AND state=?7",
            params![now_millis(),candidate.identity.taskrun_id.as_bytes(),candidate.identity.attempt_id.as_bytes(),candidate.identity.node_epoch as i64,candidate.identity.fence.0 as i64,candidate.area_identity,state.as_sql()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Retains an unresolved old effect only when this registered daemon owns its node.
    #[cfg(target_os = "linux")]
    pub fn mark_local_command_recovery_unconfirmed(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
    ) -> Result<(), EventStoreError> {
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        let state = read_exact_state(&tx, candidate)?;
        if state == LocalCommandAttemptState::OutcomeUnknown {
            let receipt_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_stop_receipts
                     WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3
                       AND managed_area_identity=?4 AND stop_kind='outcome_unknown')",
                    params![
                        candidate.identity.taskrun_id.as_bytes(),
                        candidate.identity.fence.0 as i64,
                        candidate.identity.attempt_id.as_bytes(),
                        candidate.area_identity
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| EventStoreError::CorruptData)?;
            if receipt_exists {
                return tx.commit().map_err(|_| EventStoreError::Unavailable);
            }
        }
        if state == LocalCommandAttemptState::StopUnconfirmed {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        if !matches!(
            state,
            LocalCommandAttemptState::LaunchIntent
                | LocalCommandAttemptState::ReleaseReserved
                | LocalCommandAttemptState::Running
                | LocalCommandAttemptState::CancelRequested
                | LocalCommandAttemptState::OutcomeUnknown
        ) {
            return Err(EventStoreError::CorruptData);
        }
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='stop_unconfirmed',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6 AND state=?7",
            params![now_millis(),candidate.identity.taskrun_id.as_bytes(),candidate.identity.attempt_id.as_bytes(),candidate.identity.node_epoch as i64,candidate.identity.fence.0 as i64,candidate.area_identity,state.as_sql()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
