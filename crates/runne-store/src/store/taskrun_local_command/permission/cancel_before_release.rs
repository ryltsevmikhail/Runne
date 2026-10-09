use super::cancel_event::{CancellationEvent, cancellation_event};
use super::{
    model::{load_capture, now_ms},
    stop,
    stop::read_binding,
};
use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
};
use runne_domain::task_run::TaskRunState;
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{TransactionBehavior, params};

impl StoreTransaction {
    /// Completes a V68 cancellation that won the race before the one-shot
    /// permission release: the gated child was never released, the exact
    /// managed area is proven empty, and the durable cancellation stop exists.
    /// The captured attempt records its area identity and settles through the
    /// canonical launch-intent/cancel chain (legacy parity: local/run.rs
    /// release-failure Cancelling branch). No process exit is invented.
    #[cfg(target_os = "linux")]
    pub fn complete_local_command_permission_cancelled_before_release(
        &self,
        identity: &TaskRunAssignmentIdentity,
        binding: &LocalCommandPermissionBindingV1,
        empty: VerifiedEmptyManagedArea<'_>,
    ) -> Result<(), EventStoreError> {
        let area_identity = empty.identity_bytes();
        if identity != binding.assignment() {
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
        let (digest, _) = read_binding(&tx, identity, binding)?;
        load_capture(&tx, identity, binding, false)?;
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.state != TaskRunState::Cancelling {
            return Err(EventStoreError::CorruptData);
        }
        crate::store::taskrun_claim::verify_cancelling_assignment(&tx, identity, stream.version)
            .map_err(|_| EventStoreError::CorruptData)?;
        if stop::stop_reason(
            &tx,
            identity.taskrun_id.as_bytes(),
            identity.attempt_id.as_bytes(),
            &digest,
        )? != Some(1)
        {
            return Err(EventStoreError::CorruptData);
        }
        let unreleased: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_attempts a
                   WHERE a.taskrun_id=?1 AND a.attempt_id=?2 AND a.node_epoch=?3 AND a.fence=?4
                     AND a.state='approved' AND a.managed_area_identity IS NULL
                     AND a.exit_code IS NULL
                     AND NOT EXISTS(SELECT 1 FROM x2_permission_spent s
                           WHERE s.taskrun_id=a.taskrun_id AND s.attempt_id=a.attempt_id))",
                params![
                    identity.taskrun_id.as_bytes(),
                    identity.attempt_id.as_bytes(),
                    identity.node_epoch as i64,
                    identity.fence.0 as i64
                ],
                |row| row.get(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if !unreleased {
            return Err(EventStoreError::CorruptData);
        }
        let terminal = cancellation_event(identity, &tx)?;
        let timestamp = now_ms()
            .checked_mul(1000)
            .ok_or(EventStoreError::CorruptData)?
            .max(terminal.last_timestamp);
        let (payload, event_digest, guarded) = crate::store::event_guard::guard_taskrun_event(
            self.prohibited_content.as_ref(),
            &terminal.event,
            terminal.sequence,
            terminal.position,
            timestamp,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        crate::store::append_helpers::insert_event(
            &tx,
            &terminal.event,
            crate::store::CORRELATION_TYPE_TASK_RUN,
            guarded.as_bytes(),
            terminal.sequence,
            terminal.position,
            timestamp,
            &payload,
            event_digest,
            crate::store::INTEGRITY_PROFILE_V1,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE aggregate_streams SET current_version=?1,last_event_id=?2,last_timestamp=?3
                 WHERE aggregate_type=1 AND aggregate_id=?4 AND current_version=?5
                   AND last_event_id=?6",
                params![
                    terminal.sequence as i64,
                    terminal.event.event_id().as_bytes(),
                    timestamp,
                    identity.taskrun_id.as_bytes(),
                    terminal.stream_version,
                    terminal.last_event
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        crate::store::snapshot::refresh_aggregate_snapshot(
            &tx,
            crate::store::CORRELATION_TYPE_TASK_RUN,
            identity.taskrun_id.as_bytes(),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx
            .execute(
                "UPDATE event_log_state SET next_global_position=?1
                 WHERE singleton=1 AND next_global_position=?2",
                params![
                    terminal
                        .position
                        .checked_add(1)
                        .ok_or(EventStoreError::CorruptData)?,
                    terminal.position
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        settle_unreleased_cancel(&tx, identity, area_identity, &terminal)?;
        empty
            .revalidate()
            .map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn settle_unreleased_cancel(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    area_identity: &[u8],
    terminal: &CancellationEvent,
) -> Result<(), EventStoreError> {
    let taskrun = identity.taskrun_id.as_bytes();
    let attempt = identity.attempt_id.as_bytes();
    let node = uuid::Uuid::parse_str(&identity.node_id.0)
        .map_err(|_| EventStoreError::CorruptData)?
        .as_bytes()
        .to_vec();
    let now = now_ms();
    let changed = tx
        .execute(
            "UPDATE taskrun_local_command_attempts SET managed_area_identity=?1,state='launch_intent',updated_at=?2
             WHERE taskrun_id=?3 AND attempt_id=?4 AND fence=?5 AND state='approved'
               AND executable_digest IS NULL AND approval_id IS NULL AND managed_area_identity IS NULL",
            params![area_identity, now, taskrun, attempt, identity.fence.0 as i64],
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if changed != 1 {
        return Err(EventStoreError::CorruptData);
    }
    for (from, to) in [
        ("launch_intent", "cancel_requested"),
        ("cancel_requested", "cancelled"),
    ] {
        let changed = tx
            .execute(
                "UPDATE taskrun_local_command_attempts SET state=?1,updated_at=?2
                 WHERE taskrun_id=?3 AND attempt_id=?4 AND fence=?5
                   AND managed_area_identity=?6 AND state=?7",
                params![
                    to,
                    now,
                    taskrun,
                    attempt,
                    identity.fence.0 as i64,
                    area_identity,
                    from
                ],
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
    }
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts
         (taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            taskrun,
            identity.fence.0 as i64,
            attempt,
            node,
            identity.node_epoch as i64,
            terminal.event.event_id().as_bytes(),
            terminal.sequence as i64
        ],
    )
    .map_err(|_| EventStoreError::CorruptData)?;
    let released = tx
        .execute(
            "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1
             WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5
               AND node_epoch=?6 AND state='active' AND dispatch_intent='absent'
               AND release_event_id IS NULL",
            params![
                terminal.event.event_id().as_bytes(),
                taskrun,
                identity.fence.0 as i64,
                attempt,
                node,
                identity.node_epoch as i64
            ],
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if released != 1 {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}
