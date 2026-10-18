use super::super::{LocalCommandAttemptState, LocalCommandRecoveryCandidate};
use super::helpers::{now_millis, read_exact_state};
use super::outcome_unknown_replay::replay_existing_receipt;
use super::verify_recovery_owner;
use crate::codec::{StoreCodec, TaskRunEventCodec};
use runne_application::ports::{EventStoreError, ExecutionNodeId};
use runne_domain::event::{Actor, Sensitivity, UncommittedEvent};
use runne_domain::id::{AggregateId, CommandId, EventId, IdempotencyKey};
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{TransactionBehavior, params};

mod compiled_append;

impl super::super::super::StoreTransaction {
    /// Closes a crashed local effect as unknown after proving its exact area empty.
    pub fn settle_local_command_outcome_unknown_recovery(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
        empty: VerifiedEmptyManagedArea<'_>,
    ) -> Result<(), EventStoreError> {
        if empty.identity_bytes().as_slice() != candidate.area_identity {
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
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;

        if replay_existing_receipt(&tx, candidate, current_epoch, &empty)? {
            return tx.commit().map_err(|_| EventStoreError::Unavailable);
        }
        let state = read_exact_state(&tx, candidate)?;
        if !matches!(
            state,
            LocalCommandAttemptState::LaunchIntent
                | LocalCommandAttemptState::ReleaseReserved
                | LocalCommandAttemptState::Running
                | LocalCommandAttemptState::StopUnconfirmed
        ) {
            return Err(EventStoreError::CorruptData);
        }
        let (stream_version, last_event, last_timestamp): (i64, Vec<u8>, i64) = tx
            .query_row(
                "SELECT current_version,last_event_id,last_timestamp FROM aggregate_streams
                 WHERE aggregate_type=1 AND aggregate_id=?1",
                [candidate.identity.taskrun_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            candidate.identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Running
            || stream.version != stream_version as u64
            || stream.active_attempt != Some(candidate.identity.attempt_id)
        {
            return Err(EventStoreError::CorruptData);
        }
        let (command_digest, exit_code): (Vec<u8>, Option<i32>) = tx
            .query_row(
                "SELECT command_digest,exit_code FROM taskrun_local_command_attempts
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND managed_area_identity=?4",
                params![
                    candidate.identity.taskrun_id.as_bytes(),
                    candidate.identity.attempt_id.as_bytes(),
                    candidate.identity.fence.0 as i64,
                    candidate.area_identity
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if command_digest.len() != 32 || exit_code.is_some() {
            return Err(EventStoreError::CorruptData);
        }
        let node = uuid::Uuid::parse_str(&candidate.identity.node_id.0)
            .map_err(|_| EventStoreError::CorruptData)?;
        let aggregate = AggregateId::TaskRun(candidate.identity.taskrun_id);
        let command_id = CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        let key = IdempotencyKey::new(format!(
            "local-command-recovery-unknown-v1:{}:{}:{current_epoch}",
            candidate.identity.taskrun_id, candidate.identity.fence.0
        ))
        .map_err(|_| EventStoreError::CorruptData)?;
        let actor = Actor::new("system:local_command_recovery")
            .map_err(|_| EventStoreError::CorruptData)?;
        let first_id = EventId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        let terminal_id = EventId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
        let causation = EventId::from_bytes(
            last_event
                .as_slice()
                .try_into()
                .map_err(|_| EventStoreError::CorruptData)?,
        );
        let first = UncommittedEvent::from_parts(
            first_id,
            aggregate.clone(),
            aggregate.clone(),
            Some(causation),
            command_id,
            key.clone(),
            1,
            actor.clone(),
            Sensitivity::Public,
            TaskRunEvent::ReconciliationStarted,
        );
        let second = UncommittedEvent::from_parts(
            terminal_id,
            aggregate,
            AggregateId::TaskRun(candidate.identity.taskrun_id),
            Some(first_id),
            command_id,
            key,
            1,
            actor,
            Sensitivity::Public,
            TaskRunEvent::Unrecoverable,
        );
        let now = now_millis()
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
        let first_version = stream_version
            .checked_add(1)
            .ok_or(EventStoreError::CorruptData)?;
        let terminal_version = stream_version
            .checked_add(2)
            .ok_or(EventStoreError::CorruptData)?;
        let terminal_position = position
            .checked_add(1)
            .ok_or(EventStoreError::CorruptData)?;
        let event_time = now.max(last_timestamp);
        crate::store::event_guard::append_taskrun_event(
            &tx,
            self.prohibited_content.as_ref(),
            &first,
            u64::try_from(first_version).map_err(|_| EventStoreError::CorruptData)?,
            position,
            event_time,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        compiled_append::append_terminal(
            &tx,
            self.prohibited_content.as_ref(),
            candidate,
            stream_version,
            &last_event,
            &first,
            &second,
            first_version,
            terminal_version,
            position,
            terminal_position,
            event_time,
        )?;
        let changed = tx
            .execute(
                "UPDATE taskrun_local_command_attempts SET state='outcome_unknown',updated_at=?1
                 WHERE taskrun_id=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5
                   AND fence=?6 AND managed_area_identity=?7 AND state=?8 AND exit_code IS NULL",
                params![
                    now_millis(),
                    candidate.identity.taskrun_id.as_bytes(),
                    candidate.identity.attempt_id.as_bytes(),
                    node.as_bytes(),
                    candidate.identity.node_epoch as i64,
                    candidate.identity.fence.0 as i64,
                    candidate.area_identity,
                    state.as_sql()
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        let changed = tx
            .execute(
                "UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3
                 WHERE aggregate_type=1 AND aggregate_id=?4 AND current_version=?5 AND last_event_id=?6",
                params![terminal_version,terminal_id.as_bytes(),event_time,candidate.identity.taskrun_id.as_bytes(),stream_version,last_event],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            super::super::super::CORRELATION_TYPE_TASK_RUN,
            candidate.identity.taskrun_id.as_bytes(),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE event_log_state SET next_global_position=?1 WHERE singleton=1 AND next_global_position=?2",
                params![position.checked_add(2).ok_or(EventStoreError::CorruptData)?,position],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.execute(
            "INSERT INTO taskrun_terminal_settlement_receipts
             (taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                candidate.identity.taskrun_id.as_bytes(),
                candidate.identity.fence.0 as i64,
                candidate.identity.attempt_id.as_bytes(),
                node.as_bytes(),
                candidate.identity.node_epoch as i64,
                terminal_id.as_bytes(),
                terminal_version
            ],
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let released = tx
            .execute(
                "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1
                 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6
                   AND state='active' AND dispatch_intent='absent' AND release_event_id IS NULL",
                params![
                    terminal_id.as_bytes(),
                    candidate.identity.taskrun_id.as_bytes(),
                    candidate.identity.fence.0 as i64,
                    candidate.identity.attempt_id.as_bytes(),
                    node.as_bytes(),
                    candidate.identity.node_epoch as i64
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if released != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.execute(
            "INSERT INTO taskrun_local_command_stop_receipts
             (taskrun_id,fence,attempt_id,historic_node_id,historic_node_epoch,proof_node_id,
              proof_node_epoch,managed_area_identity,command_digest,stop_kind,terminal_event_id,terminal_version)
             VALUES(?1,?2,?3,?4,?5,?4,?6,?7,?8,'outcome_unknown',?9,?10)",
            params![candidate.identity.taskrun_id.as_bytes(),candidate.identity.fence.0 as i64,candidate.identity.attempt_id.as_bytes(),node.as_bytes(),candidate.identity.node_epoch as i64,current_epoch as i64,candidate.area_identity,command_digest,terminal_id.as_bytes(),terminal_version],
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        let terminal_payload: Vec<u8> = tx
            .query_row(
                "SELECT payload FROM events WHERE event_id=?1",
                [terminal_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if TaskRunEventCodec
            .decode(&terminal_payload)
            .map_err(|_| EventStoreError::CorruptData)?
            != TaskRunEvent::Unrecoverable
        {
            return Err(EventStoreError::CorruptData);
        }
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
