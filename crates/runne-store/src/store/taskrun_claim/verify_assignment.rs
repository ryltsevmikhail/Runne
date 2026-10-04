use super::*;
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::OptionalExtension;

pub(crate) fn verify_assignment_history(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
) -> Result<TaskRun, ClaimError> {
    let row: Option<ClaimAuthorityRow> = connection
        .query_row(
            "SELECT command_id,idempotency_key,taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,new_version,admitted_event_id,started_event_id FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![identity.taskrun_id.as_bytes(), identity.fence.0],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
        )
        .optional()
        .map_err(|_| ClaimError::CorruptData)?;
    let Some((
        command,
        key,
        taskrun,
        attempt,
        node,
        epoch,
        fence,
        expiry,
        version,
        admitted,
        started,
    )) = row
    else {
        return Err(ClaimError::CorruptData);
    };
    let receipt = receipts::receipt(
        taskrun, attempt, node, epoch, fence, expiry, version, admitted, started,
    )?;
    if receipt.taskrun_id != identity.taskrun_id
        || receipt.attempt_id != identity.attempt_id
        || receipt.node_id.0 != identity.node_id.0
        || receipt.node_epoch != identity.node_epoch
        || receipt.fence != identity.fence
    {
        return Err(ClaimError::CorruptData);
    }
    let command = CommandId::from_bytes(command.try_into().map_err(|_| ClaimError::CorruptData)?);
    receipts::verify_assignment(connection, &receipt, command)?;
    stream_integrity::verify_claim_stream_task(connection, &receipt, command, &key)
}

pub(in crate::store) fn verify_active_assignment(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
) -> Result<(), ClaimError> {
    let task = verify_assignment_history(connection, identity)?;
    if task.state() != TaskRunState::Running || task.active_attempt() != Some(&identity.attempt_id)
    {
        return Err(ClaimError::NotQueued);
    }
    Ok(())
}
