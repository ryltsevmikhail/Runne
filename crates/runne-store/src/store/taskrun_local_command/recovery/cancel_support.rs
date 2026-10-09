use super::LocalCommandRecoveryCandidate;
use crate::codec::{StoreCodec, TaskRunEventCodec};
use runne_application::ports::EventStoreError;
use runne_domain::task_run::TaskRunEvent;
use rusqlite::{Connection, OptionalExtension, params};

/// Returns the (version, event id) of the last durable `CancellationRequested`
/// event of the TaskRun stream: the exact reference a permission stop row must
/// cite, and the proof ingredient a recovery completion records when the live
/// cancel unit of work never committed one.
pub(super) fn cancellation_stop_reference(
    connection: &Connection,
    taskrun_id: runne_domain::id::TaskRunId,
) -> Result<Option<(u64, Vec<u8>)>, EventStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence,event_id,payload FROM events
             WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence",
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let rows = statement
        .query_map([taskrun_id.as_bytes()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|_| EventStoreError::CorruptData)?;
    let mut reference = None;
    for row in rows {
        let (sequence, event_id, payload) = row.map_err(|_| EventStoreError::CorruptData)?;
        if matches!(
            TaskRunEventCodec.decode(&payload),
            Ok(TaskRunEvent::CancellationRequested)
        ) {
            let version = u64::try_from(sequence).map_err(|_| EventStoreError::CorruptData)?;
            reference = Some((version, event_id));
        }
    }
    Ok(reference)
}

/// Loads and fully validates the retained x2 binding of one attempt the way
/// the live `read_binding` does — blob decodes canonically, the domain digest
/// matches, the route is CurrentPermission, the fence, attempt, native owner,
/// selection policy, command digest and node identity all agree with the
/// durable rows — and returns its exact binding digest. `Ok(None)` means no
/// binding row exists; any tampered or mismatched row is `CorruptData`.
type BindingRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
);

pub(super) fn verified_binding_digest(
    connection: &Connection,
    taskrun_id: &runne_domain::id::TaskRunId,
    attempt_id: &runne_domain::id::AttemptId,
) -> Result<Option<[u8; 32]>, EventStoreError> {
    let row: Option<BindingRow> = connection
        .query_row(
            "SELECT b.binding_digest,b.binding,b.fence,b.native_owner_id,b.native_owner_generation,
                    b.selection_managed_policy_version,b.selection_managed_policy_digest,
                    a.command_digest,x.node_id,x.node_epoch,r.route
             FROM x2_permission_bindings b
             JOIN taskrun_local_permission_routes r USING(taskrun_id)
             JOIN taskrun_local_command_attempts a USING(taskrun_id)
             JOIN taskrun_assignments x
               ON x.taskrun_id=b.taskrun_id AND x.fence=b.fence AND x.attempt_id=b.attempt_id
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((
        digest,
        blob,
        fence,
        owner,
        generation,
        policy_version,
        policy_digest,
        command,
        node,
        node_epoch,
        route,
    )) = row
    else {
        return Ok(None);
    };
    let record =
        super::super::permission::codec::decode(&blob).map_err(|_| EventStoreError::CorruptData)?;
    let digest: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| EventStoreError::CorruptData)?;
    if !super::super::permission::codec::digest_matches(&blob, &digest)
        || route != 2
        || record.taskrun_id.as_slice() != taskrun_id.as_bytes()
        || record.attempt_id.as_slice() != attempt_id.as_bytes()
        || record.fence != u64::try_from(fence).unwrap_or(0)
        || record.command_digest.as_slice() != command.as_slice()
        || record.native_owner_id.as_slice() != owner.as_slice()
        || record.native_owner_generation.to_be_bytes().as_slice() != generation.as_slice()
        || record.selection_managed_policy_version
            != u64::try_from(policy_version).unwrap_or(u64::MAX)
        || record.selection_managed_policy_digest.as_slice() != policy_digest.as_slice()
        || record.node_epoch != u64::try_from(node_epoch).unwrap_or(u64::MAX)
        || uuid::Uuid::parse_str(&record.node_id)
            .map(|parsed| parsed.as_bytes().as_slice() != node.as_slice())
            .unwrap_or(true)
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(Some(digest))
}

/// Records the canonical first-writer stop row inside the completion unit of
/// work. The recovery itself proved the managed area empty before this call,
/// so citing the last durable `CancellationRequested` event with the exactly
/// validated binding digest is the same evidence class the live cancel commit
/// writes. The postcondition is strict: after the first-writer insert the
/// durable stop must read back as the cancellation reason — an already
/// retained non-cancellation stop is an integrity conflict, never overwritten
/// and never reported as proven cancellation.
pub(super) fn record_recovery_stop(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
) -> Result<(), EventStoreError> {
    let Some(digest) = verified_binding_digest(
        tx,
        &candidate.identity.taskrun_id,
        &candidate.identity.attempt_id,
    )?
    else {
        return Err(EventStoreError::CorruptData);
    };
    let Some((version, event_id)) = cancellation_stop_reference(tx, candidate.identity.taskrun_id)?
    else {
        return Err(EventStoreError::CorruptData);
    };
    let taskrun = candidate.identity.taskrun_id.as_bytes();
    let attempt = candidate.identity.attempt_id.as_bytes();
    super::super::permission::stop::record_stop(
        tx,
        taskrun,
        attempt,
        &digest,
        1,
        version,
        &event_id,
        super::helpers::now_millis(),
    )?;
    if super::super::permission::stop::read_stop(tx, taskrun, attempt, &digest)? != Some(1) {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

/// Commits the settlement receipt and releases the occupation. The attempt
/// row already carries its exact terminal state (`cancelled` after the stop
/// proof, or `completed` when a factual exit preceded the cancellation), so
/// SQL failures and zero-row updates are errors, not noise.
pub(super) fn settle_cancellation_receipt_and_release(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
    node: uuid::Uuid,
    terminal_event: &runne_domain::id::EventId,
    sequence: i64,
    terminal_state_was_cancel_requested: bool,
) -> Result<(), EventStoreError> {
    let taskrun = candidate.identity.taskrun_id.as_bytes();
    let attempt = candidate.identity.attempt_id.as_bytes();
    if terminal_state_was_cancel_requested {
        let changed = tx
            .execute(
                "UPDATE taskrun_local_command_attempts SET state='cancelled',updated_at=?1
                 WHERE taskrun_id=?2 AND attempt_id=?3 AND fence=?4 AND managed_area_identity=?5
                   AND state='cancel_requested'",
                params![
                    super::helpers::now_millis(),
                    taskrun,
                    attempt,
                    candidate.identity.fence.0 as i64,
                    candidate.area_identity
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
            candidate.identity.fence.0 as i64,
            attempt,
            node.as_bytes(),
            candidate.identity.node_epoch as i64,
            terminal_event.as_bytes(),
            sequence
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
                terminal_event.as_bytes(),
                taskrun,
                candidate.identity.fence.0 as i64,
                attempt,
                node.as_bytes(),
                candidate.identity.node_epoch as i64
            ],
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if released != 1 {
        let already_released: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_assignment_occupations
                 WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4
                   AND node_epoch=?5 AND state='released' AND dispatch_intent='absent'
                   AND release_event_id=?6)",
                params![
                    taskrun,
                    candidate.identity.fence.0 as i64,
                    attempt,
                    node.as_bytes(),
                    candidate.identity.node_epoch as i64,
                    terminal_event.as_bytes()
                ],
                |row| row.get(0),
            )
            .map_err(|_| EventStoreError::CorruptData)?;
        if !already_released {
            return Err(EventStoreError::CorruptData);
        }
    }
    Ok(())
}
