use super::super::*;
use super::recovery::{LocalCommandRecoveryCandidate, verify_recovery_owner};
use super::run::verify_empty_proof;
use crate::codec::TaskRunEventCodec;
use runne_application::ports::{EventStoreError, ExecutionNodeId, TaskRunAssignmentIdentity};
use runne_domain::id::EventId;
use runne_domain::task_run::{TaskRunEvent, TaskRunState};
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl StoreTransaction {
    /// Commits terminal receipt and releases occupation after exact empty proof.
    pub fn settle_local_command_terminal(
        &self,
        identity: &TaskRunAssignmentIdentity,
        area_identity: &[u8],
        terminal_event: EventId,
        terminal_version: u64,
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
        verify_terminal_assignment(&tx, identity, terminal_event, terminal_version)?;
        settle(
            &tx,
            identity,
            area_identity,
            terminal_event,
            terminal_version,
        )?;
        verify_empty_proof(&empty, area_identity)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Settles an old exact attempt only under this daemon's fresh registered epoch.
    pub fn settle_local_command_terminal_recovery(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
        terminal_event: EventId,
        terminal_version: u64,
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
        super::permission::require_legacy_bound_route(&tx, candidate.identity.taskrun_id)?;
        verify_empty_proof(&empty, &candidate.area_identity)?;
        verify_recovery_owner(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        settle(
            &tx,
            &candidate.identity,
            &candidate.area_identity,
            terminal_event,
            terminal_version,
        )?;
        verify_empty_proof(&empty, &candidate.area_identity)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}

pub(super) fn verify_terminal_assignment(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    terminal_event: EventId,
    terminal_version: u64,
) -> Result<(), EventStoreError> {
    let node =
        uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?;
    let valid: bool = tx
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM taskrun_assignments a
               JOIN taskrun_claim_receipts c ON c.taskrun_id=a.taskrun_id AND c.fence=a.fence
               JOIN taskrun_assignment_occupations o ON o.taskrun_id=a.taskrun_id AND o.fence=a.fence
               WHERE a.taskrun_id=?1 AND a.attempt_id=?2 AND a.node_id=?3 AND a.node_epoch=?4 AND a.fence=?5
                 AND c.attempt_id=a.attempt_id AND c.node_id=a.node_id AND c.node_epoch=a.node_epoch
                 AND c.command_id=a.command_id AND c.admitted_event_id=a.admitted_event_id
                 AND c.started_event_id=a.started_event_id
                 AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id AND o.node_epoch=a.node_epoch
                 AND o.dispatch_intent='absent'
                 AND ((o.state='active' AND o.release_event_id IS NULL
                       AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
                                      WHERE r.taskrun_id=a.taskrun_id AND r.fence=a.fence))
                   OR (o.state='released' AND o.release_event_id=?6
                       AND EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
                                  WHERE r.taskrun_id=a.taskrun_id AND r.fence=a.fence
                                    AND r.attempt_id=a.attempt_id AND r.node_id=a.node_id
                                    AND r.node_epoch=a.node_epoch AND r.terminal_event_id=?6
                                    AND r.terminal_version=?7)))
             )",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes(),
                node.as_bytes(),
                identity.node_epoch as i64,
                identity.fence.0 as i64,
                terminal_event.as_bytes(),
                terminal_version as i64,
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if valid {
        Ok(())
    } else {
        Err(EventStoreError::CorruptData)
    }
}

pub(super) fn settle(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    area_identity: &[u8],
    terminal_event: EventId,
    terminal_version: u64,
) -> Result<(), EventStoreError> {
    let stream =
        super::super::taskrun_claim::stream_validate::verify_stream(tx, identity.taskrun_id, None)
            .map_err(|_| EventStoreError::CorruptData)?;
    let last_event: Vec<u8> = tx
        .query_row(
            "SELECT last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [identity.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let route: Option<(i64, i64, i64)> = tx
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [identity.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let current_permission = route == Some((2, 3, 68));
    if !current_permission && route != Some((1, 1, 68)) {
        return Err(EventStoreError::CorruptData);
    }
    if stream.version != terminal_version
        || last_event.as_slice() != terminal_event.as_bytes()
        || !(matches!(stream.state, TaskRunState::Succeeded | TaskRunState::Failed)
            || (current_permission && stream.state == TaskRunState::Cancelled))
    {
        return Err(EventStoreError::CorruptData);
    }
    let terminal_payload: Vec<u8> = tx
        .query_row(
            "SELECT payload FROM events WHERE event_id=?1 AND aggregate_type=1 AND aggregate_id=?2 AND sequence=?3",
            params![terminal_event.as_bytes(), identity.taskrun_id.as_bytes(), terminal_version as i64],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let terminal = TaskRunEventCodec
        .decode(&terminal_payload)
        .map_err(|_| EventStoreError::CorruptData)?;
    let proof: Option<(String, Option<i32>, Vec<u8>)> = tx
        .query_row(
            "SELECT state,exit_code,node_id FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4 AND managed_area_identity=?5",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((state, Some(exit_code), node)) = proof else {
        return Err(EventStoreError::CorruptData);
    };
    let node_uuid =
        uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?;
    let permission_policy_stop = current_permission
        && state == "cancelled"
        && stream.state == TaskRunState::Failed
        && matches!(
            &terminal,
            TaskRunEvent::TaskRunFailed { reason }
                if reason.as_str() == "local_command_policy_stopped_v1"
        );
    if (state != "completed"
        && !(current_permission && state == "cancelled" && stream.state == TaskRunState::Cancelled)
        && !permission_policy_stop)
        || node.as_slice() != node_uuid.as_bytes()
        || !super::permission::terminal_matches_exit(
            &terminal,
            &stream.state,
            exit_code,
            current_permission,
        )
    {
        return Err(EventStoreError::CorruptData);
    }
    settle_receipt(tx, identity, node_uuid, terminal_event, terminal_version)
}

fn settle_receipt(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    node: uuid::Uuid,
    terminal_event: EventId,
    terminal_version: u64,
) -> Result<(), EventStoreError> {
    type PriorReceipt = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64);
    let prior: Option<PriorReceipt> = tx
        .query_row(
            "SELECT terminal_event_id,terminal_version,attempt_id,node_id,node_epoch
             FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?2",
            params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64],
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
    if let Some((event, version, attempt, receipt_node, epoch)) = prior {
        let expected_node =
            uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?;
        return if event.as_slice() == terminal_event.as_bytes()
            && version == terminal_version as i64
            && attempt.as_slice() == identity.attempt_id.as_bytes()
            && receipt_node.as_slice() == expected_node.as_bytes()
            && epoch == identity.node_epoch as i64
            && occupation_released(tx, identity, node, terminal_event)?
        {
            Ok(())
        } else {
            Err(EventStoreError::CorruptData)
        };
    }
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node.as_bytes(),identity.node_epoch as i64,terminal_event.as_bytes(),terminal_version as i64],
    ).map_err(|_| EventStoreError::CorruptData)?;
    let released = tx.execute(
        "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND dispatch_intent='absent' AND release_event_id IS NULL",
        params![terminal_event.as_bytes(),identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node.as_bytes(),identity.node_epoch as i64],
    ).map_err(|_| EventStoreError::CorruptData)?;
    if released == 1 {
        Ok(())
    } else {
        Err(EventStoreError::CorruptData)
    }
}

fn occupation_released(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    node: uuid::Uuid,
    terminal_event: EventId,
) -> Result<bool, EventStoreError> {
    let occupation: Option<(String, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT state,release_event_id FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
            params![identity.taskrun_id.as_bytes(),identity.fence.0 as i64,identity.attempt_id.as_bytes(),node.as_bytes(),identity.node_epoch as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    Ok(occupation.as_ref().is_some_and(|(state, release)| {
        state == "released" && release.as_deref() == Some(terminal_event.as_bytes())
    }))
}
