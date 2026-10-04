use super::super::LocalCommandAttemptState;
use super::super::LocalCommandRecoveryCandidate;
use super::helpers::{now_millis, read_exact_state};
use super::verify_recovery_owner;
use runne_application::ports::{EventStoreError, ExecutionNodeId};
use runne_domain::task_run::TaskRunState;
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{TransactionBehavior, params};

impl super::super::super::StoreTransaction {
    /// Commits an exact recovery stop proof without pretending an old node epoch is live.
    pub fn confirm_local_command_stopped_recovery(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
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
        if empty.identity_bytes().as_slice() != candidate.area_identity
            || empty.revalidate().is_err()
        {
            return Err(EventStoreError::CorruptData);
        }
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        let stream = super::super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            candidate.identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Cancelling {
            return Err(EventStoreError::CorruptData);
        }
        let state = read_exact_state(&tx, candidate)?;
        if state == LocalCommandAttemptState::Cancelled {
            revalidate(&empty)?;
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        if !matches!(
            state,
            LocalCommandAttemptState::CancelRequested
                | LocalCommandAttemptState::StopUnconfirmed
                | LocalCommandAttemptState::OutcomeUnknown
        ) {
            return Err(EventStoreError::CorruptData);
        }
        revalidate(&empty)?;
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='cancelled',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6 AND state=?7",
            params![now_millis(),candidate.identity.taskrun_id.as_bytes(),candidate.identity.attempt_id.as_bytes(),candidate.identity.node_epoch as i64,candidate.identity.fence.0 as i64,candidate.area_identity,state.as_sql()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        revalidate(&empty)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}

fn revalidate(empty: &VerifiedEmptyManagedArea<'_>) -> Result<(), EventStoreError> {
    empty.revalidate().map_err(|_| EventStoreError::CorruptData)
}
