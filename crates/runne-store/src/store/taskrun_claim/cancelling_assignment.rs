use super::*;

pub(super) fn verify(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    expected_version: u64,
) -> Result<(), ClaimError> {
    let row: Option<ClaimAuthorityRow> = connection.query_row(
        "SELECT command_id,idempotency_key,taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,new_version,admitted_event_id,started_event_id FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![identity.taskrun_id.as_bytes(), identity.fence.0],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
    ).optional().map_err(|_| ClaimError::CorruptData)?;
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
        || receipt.node_id != identity.node_id
        || receipt.node_epoch != identity.node_epoch
        || receipt.fence != identity.fence
        || receipt.new_version >= expected_version
    {
        return Err(ClaimError::CorruptData);
    }
    let command = CommandId::from_bytes(command.try_into().map_err(|_| ClaimError::CorruptData)?);
    let key = String::from_utf8(key).map_err(|_| ClaimError::CorruptData)?;
    let _ = IdempotencyKey::new(key.clone()).map_err(|_| ClaimError::CorruptData)?;
    receipts::verify_assignment(connection, &receipt, command)?;
    let task =
        stream_integrity::verify_claim_stream_task(connection, &receipt, command, key.as_bytes())?;
    let current =
        stream_validate::verify_stream(connection, identity.taskrun_id, Some(expected_version))?;
    if current.state != TaskRunState::Cancelling
        || task.state() != TaskRunState::Cancelling
        || task.active_attempt() != Some(&identity.attempt_id)
    {
        return Err(ClaimError::NotQueued);
    }
    Ok(())
}
