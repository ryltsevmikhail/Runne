use super::super::*;
use runne_domain::id::{AttemptId, EventId, TaskRunId};
use runne_domain::task_run::TaskRunEvent;
use rusqlite::{OptionalExtension, Transaction};

pub(crate) struct LocalEffectsProofRequest<'a> {
    pub(crate) taskrun_id: TaskRunId,
    pub(crate) attempt: Option<AttemptId>,
    pub(crate) area_identity: Option<&'a [u8]>,
    pub(crate) command_digest: &'a [u8],
    pub(crate) state: &'a str,
    pub(crate) stream_version: u64,
    pub(crate) head_event_id: Option<EventId>,
    pub(crate) head_event: Option<&'a TaskRunEvent>,
}

struct LocalEffectsProofRow {
    attempt_id: Vec<u8>,
    node_id: Vec<u8>,
    node_epoch: i64,
    fence: i64,
    area_identity: Vec<u8>,
    command_digest: Vec<u8>,
    state: String,
}

/// Verifies a local stop/terminal assertion against the already-open effects snapshot.
pub(crate) fn terminal_stop_proven(
    tx: &Transaction<'_>,
    proof: LocalEffectsProofRequest<'_>,
) -> Result<bool, EventStoreError> {
    let LocalEffectsProofRequest {
        taskrun_id,
        attempt,
        area_identity,
        command_digest,
        state,
        stream_version,
        head_event_id,
        head_event,
    } = proof;
    if !matches!(state, "completed" | "cancelled" | "outcome_unknown") {
        return Ok(false);
    }
    let (Some(attempt), Some(requested_area), Some(head_id), Some(event)) =
        (attempt, area_identity, head_event_id, head_event)
    else {
        return Err(EventStoreError::CorruptData);
    };
    if command_digest.len() != 32 {
        return Err(EventStoreError::CorruptData);
    }
    let version = i64::try_from(stream_version).map_err(|_| EventStoreError::CorruptData)?;
    let head: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT current_version,last_event_id FROM aggregate_streams
             WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    if !head.is_some_and(|(current, event_id)| {
        current == version && event_id.as_slice() == head_id.as_bytes()
    }) {
        return Err(EventStoreError::CorruptData);
    }
    let local: Option<LocalEffectsProofRow> = tx
        .query_row(
            "SELECT attempt_id,node_id,node_epoch,fence,managed_area_identity,command_digest,state
             FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| {
                Ok(LocalEffectsProofRow {
                    attempt_id: row.get(0)?,
                    node_id: row.get(1)?,
                    node_epoch: row.get(2)?,
                    fence: row.get(3)?,
                    area_identity: row.get(4)?,
                    command_digest: row.get(5)?,
                    state: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some(local) = local else {
        return Err(EventStoreError::CorruptData);
    };
    if local.attempt_id.as_slice() != attempt.as_bytes()
        || local.area_identity.as_slice() != requested_area
        || Some(local.area_identity.as_slice()) != area_identity
        || local.command_digest.as_slice() != command_digest
        || local.state != state
        || local.node_epoch <= 0
        || local.fence <= 0
        || local.node_id.len() != 16
    {
        return Err(EventStoreError::CorruptData);
    }
    let (attempt_bytes, node, node_epoch, fence) = (
        attempt.as_bytes(),
        local.node_id,
        local.node_epoch,
        local.fence,
    );
    if state == "outcome_unknown" {
        return crate::schema::local_stop_terminal_proof_matches(
            tx,
            taskrun_id.as_bytes(),
            attempt_bytes,
            &node,
            node_epoch,
            fence,
            event,
        )
        .map_err(|_| EventStoreError::CorruptData);
    }
    let settled: bool = tx
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM taskrun_terminal_settlement_receipts r
               JOIN taskrun_assignments a ON a.taskrun_id=r.taskrun_id AND a.fence=r.fence
               JOIN taskrun_claim_receipts c ON c.taskrun_id=a.taskrun_id AND c.fence=a.fence
               JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
               WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.node_id=?3
                 AND r.node_epoch=?4 AND r.fence=?5 AND r.terminal_event_id=?6
                 AND r.terminal_version=?7 AND a.attempt_id=r.attempt_id
                 AND a.node_id=r.node_id AND a.node_epoch=r.node_epoch
                 AND c.attempt_id=a.attempt_id AND c.node_id=a.node_id
                 AND c.node_epoch=a.node_epoch AND c.new_version=4
                 AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id
                 AND o.node_epoch=a.node_epoch AND o.dispatch_intent='absent'
                 AND o.state='released' AND o.release_event_id=r.terminal_event_id
             )",
            rusqlite::params![
                taskrun_id.as_bytes(),
                attempt_bytes,
                node,
                node_epoch,
                fence,
                head_id.as_bytes(),
                version,
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if !settled
        || !crate::schema::local_terminal_proof_matches(
            tx,
            taskrun_id.as_bytes(),
            attempt_bytes,
            &node,
            node_epoch,
            fence,
            event,
        )
        .map_err(|_| EventStoreError::CorruptData)?
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(true)
}
