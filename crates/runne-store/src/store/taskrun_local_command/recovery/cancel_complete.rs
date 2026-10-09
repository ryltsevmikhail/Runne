use super::super::{LocalCommandAttemptState, LocalCommandRecoveryCandidate};
use super::cancel_settled::settled_cancellation_matches;
use super::cancel_support::{record_recovery_stop, settle_cancellation_receipt_and_release};
use super::helpers::read_exact_state;
use super::verify_recovery_owner;
use runne_application::ports::{EventStoreError, ExecutionNodeId};
use runne_domain::event::{Actor, Sensitivity, UncommittedEvent};
use runne_domain::id::{AggregateId, CommandId, EventId, IdempotencyKey};
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl super::super::super::StoreTransaction {
    /// Completes a crashed V68 CurrentPermission cancellation after its exact
    /// area was proven empty.
    ///
    /// The common terminal guard stays intact: this recovery-owned transaction
    /// is the only writer of this terminal, and only after the durable
    /// cancellation stop evidence, the recovery owner, the empty area, and the
    /// still-active claimed attempt have all been revalidated in one commit.
    /// The attempt keeps its exact terminal facts: a factual exit recorded
    /// before the cancellation stays authoritative (no exit is invented into
    /// the event, none is erased from the row), and a stop without an observed
    /// exit keeps `exit_code` NULL. An exactly settled candidate returns
    /// without any new write, independent of the recovery epoch.
    #[cfg(target_os = "linux")]
    pub fn complete_local_command_cancellation_recovery(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
        empty: VerifiedEmptyManagedArea<'_>,
    ) -> Result<(), EventStoreError> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        if settled_cancellation_matches(&tx, candidate)? {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        if empty.identity_bytes().as_slice() != candidate.area_identity {
            return Err(EventStoreError::CorruptData);
        }
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            candidate.identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let durable_version: u64 = u64::try_from(
            tx.query_row(
                "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
                [candidate.identity.taskrun_id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Cancelling
            || stream.active_attempt != Some(candidate.identity.attempt_id)
            || stream.version != durable_version
        {
            return Err(EventStoreError::CorruptData);
        }
        let state = read_exact_state(&tx, candidate)?;
        if !matches!(
            state,
            LocalCommandAttemptState::CancelRequested
                | LocalCommandAttemptState::Cancelled
                | LocalCommandAttemptState::Completed
        ) {
            return Err(EventStoreError::CorruptData);
        }
        let taskrun = candidate.identity.taskrun_id.as_bytes();
        let attempt = candidate.identity.attempt_id.as_bytes();
        let route: Option<(i64, i64, i64)> = tx
            .query_row(
                "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
                 WHERE taskrun_id=?1",
                [taskrun],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?;
        let durable_cancel_stop: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM x2_permission_stop
                  WHERE taskrun_id=?1 AND attempt_id=?2 AND reason=1)",
                params![taskrun, attempt],
                |row| row.get(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let (exit_code, command_digest): (Option<i32>, Vec<u8>) = tx
            .query_row(
                "SELECT exit_code,command_digest FROM taskrun_local_command_attempts
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND managed_area_identity=?4",
                params![
                    taskrun,
                    attempt,
                    candidate.identity.fence.0 as i64,
                    candidate.area_identity
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let exit_shape_ok = match (&state, exit_code) {
            (LocalCommandAttemptState::Completed, Some(code)) => (0..=255).contains(&code),
            (
                LocalCommandAttemptState::CancelRequested | LocalCommandAttemptState::Cancelled,
                exit,
            ) => exit.is_none_or(|code| (0..=255).contains(&code)),
            _ => false,
        };
        if route != Some((2, 3, 68)) || !exit_shape_ok || command_digest.len() != 32 {
            return Err(EventStoreError::CorruptData);
        }
        if !durable_cancel_stop {
            record_recovery_stop(&tx, candidate)?;
        }
        let node = uuid::Uuid::parse_str(&candidate.identity.node_id.0)
            .map_err(|_| EventStoreError::CorruptData)?;
        let (stream_version, last_event, last_timestamp): (i64, Vec<u8>, i64) = tx
            .query_row(
                "SELECT current_version,last_event_id,last_timestamp FROM aggregate_streams
                 WHERE aggregate_type=1 AND aggregate_id=?1",
                [taskrun],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let causation: [u8; 16] = last_event
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?;
        let aggregate = AggregateId::TaskRun(candidate.identity.taskrun_id);
        let command_id = CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        let key = IdempotencyKey::new(format!(
            "local-command-recovery-cancel-v1:{}:{}",
            candidate.identity.taskrun_id, candidate.identity.fence.0
        ))
        .map_err(|_| EventStoreError::CorruptData)?;
        let actor = Actor::new("system:local_command_recovery")
            .map_err(|_| EventStoreError::CorruptData)?;
        let terminal = UncommittedEvent::from_parts(
            EventId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            aggregate.clone(),
            aggregate,
            Some(EventId::from_bytes(causation)),
            command_id,
            key,
            1,
            actor,
            Sensitivity::Public,
            TaskRunEvent::CancellationCompleted,
        );
        let timestamp = super::helpers::now_millis()
            .checked_mul(1_000)
            .ok_or(EventStoreError::CorruptData)?
            .max(last_timestamp);
        let position: i64 = tx
            .query_row(
                "SELECT next_global_position FROM event_log_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let sequence = stream_version
            .checked_add(1)
            .ok_or(EventStoreError::CorruptData)?;
        let (payload, digest, guarded) = crate::store::event_guard::guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &terminal,
            sequence as u64,
            position,
            timestamp,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if guarded != candidate.identity.taskrun_id {
            return Err(EventStoreError::CorruptData);
        }
        crate::store::append_helpers::insert_event(
            &tx,
            &terminal,
            crate::store::CORRELATION_TYPE_TASK_RUN,
            guarded.as_bytes(),
            sequence as u64,
            position,
            timestamp,
            &payload,
            digest,
            crate::store::INTEGRITY_PROFILE_V1,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3
                 WHERE aggregate_type=1 AND aggregate_id=?4 AND current_version=?5
                   AND last_event_id=?6",
                params![
                    sequence,
                    terminal.event_id().as_bytes(),
                    timestamp,
                    taskrun,
                    stream_version,
                    last_event
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            crate::store::CORRELATION_TYPE_TASK_RUN,
            taskrun,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE event_log_state SET next_global_position=?1
                 WHERE singleton=1 AND next_global_position=?2",
                params![
                    position
                        .checked_add(1)
                        .ok_or(EventStoreError::CorruptData)?,
                    position
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        settle_cancellation_receipt_and_release(
            &tx,
            candidate,
            node,
            terminal.event_id(),
            sequence,
            matches!(state, LocalCommandAttemptState::CancelRequested),
        )?;
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
