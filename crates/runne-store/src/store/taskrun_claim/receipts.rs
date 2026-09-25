use super::*;
use runne_domain::id::IdempotencyKey;
use rusqlite::{Connection, OptionalExtension};

pub(super) fn lookup(
    connection: &Connection,
    command_id: CommandId,
    key: &[u8],
    scope: &[u8],
    fingerprint: &[u8],
) -> Result<TaskRunClaimLookupResult, ClaimError> {
    let result = lookup_inner(connection, command_id, key, scope, fingerprint)?;
    if result.is_none() {
        ensure_external_identity_free(connection, command_id, scope, key)?;
    }
    Ok(result.map_or(
        TaskRunClaimLookupResult::Miss,
        TaskRunClaimLookupResult::Duplicate,
    ))
}

pub(super) fn lookup_tx(
    tx: &Connection,
    command_id: CommandId,
    key: &[u8],
    scope: &[u8],
    fingerprint: &[u8],
) -> Result<Option<TaskRunClaimReceipt>, ClaimError> {
    lookup_inner(tx, command_id, key, scope, fingerprint)
}

fn lookup_inner(
    connection: &Connection,
    command_id: CommandId,
    key: &[u8],
    scope: &[u8],
    fingerprint: &[u8],
) -> Result<Option<TaskRunClaimReceipt>, ClaimError> {
    let by_command = read_receipt(
        connection,
        "command_id=?1",
        rusqlite::params![command_id.as_bytes()],
    )?;
    let row = if by_command.is_some() {
        by_command
    } else {
        read_receipt(
            connection,
            "idempotency_scope_bytes=?1 AND idempotency_key=?2",
            rusqlite::params![scope, key],
        )?
    };
    let Some((
        stored_command,
        stored_scope,
        stored_key,
        stored_fp,
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
        return Ok(None);
    };
    if stored_command.len() != 16
        || stored_fp.len() != 32
        || [
            taskrun.as_slice(),
            attempt.as_slice(),
            node.as_slice(),
            admitted.as_slice(),
            started.as_slice(),
        ]
        .iter()
        .any(|value| value.len() != 16 || value.iter().all(|byte| *byte == 0))
        || epoch <= 0
        || fence <= 0
        || expiry <= 0
        || version <= 0
    {
        return Err(ClaimError::CorruptData);
    }
    IdempotencyScopeCodec
        .decode(&stored_scope)
        .map_err(|_| ClaimError::CorruptData)?;
    let stored_key_text = std::str::from_utf8(&stored_key).map_err(|_| ClaimError::CorruptData)?;
    IdempotencyKey::new(stored_key_text).map_err(|_| ClaimError::CorruptData)?;
    if stored_command.as_slice() != command_id.as_bytes()
        || stored_scope != scope
        || stored_key != key
        || stored_fp.as_slice() != fingerprint
    {
        return Err(ClaimError::IdempotencyConflict);
    }
    let decoded = receipt(
        taskrun, attempt, node, epoch, fence, expiry, version, admitted, started,
    )?;
    verify_assignment(connection, &decoded, command_id)?;
    super::stream_integrity::verify_claim_stream(connection, &decoded, command_id, key)?;
    Ok(Some(decoded))
}

type AssignmentRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    String,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn verify_assignment(
    connection: &Connection,
    receipt: &TaskRunClaimReceipt,
    command_id: CommandId,
) -> Result<(), ClaimError> {
    let assignment: Option<AssignmentRow> = connection.query_row(
        "SELECT attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id FROM taskrun_assignments WHERE taskrun_id=?1 AND fence=?2",
        rusqlite::params![receipt.taskrun_id.as_bytes(), receipt.fence.0],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)),
    ).optional().map_err(|_| ClaimError::CorruptData)?;
    let Some((attempt, node, epoch, fence, descriptor, expiry, command, admitted, started)) =
        assignment
    else {
        return Err(ClaimError::CorruptData);
    };
    let node_id = uuid::Uuid::parse_str(&receipt.node_id.0).map_err(|_| ClaimError::CorruptData)?;
    if attempt.as_slice() != receipt.attempt_id.as_bytes()
        || node.as_slice() != node_id.as_bytes()
        || epoch != receipt.node_epoch as i64
        || fence != receipt.fence.0 as i64
        || descriptor != LINUX_CAPABILITY_DESCRIPTOR
        || expiry.checked_mul(1000) != Some(receipt.lease_expires_at.as_unix_micros())
        || command.as_slice() != command_id.as_bytes()
        || admitted.as_slice() != receipt.admitted_event_id.as_bytes()
        || started.as_slice() != receipt.started_event_id.as_bytes()
    {
        return Err(ClaimError::CorruptData);
    }
    Ok(())
}

type CompleteReceiptRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
);

fn read_receipt<P: rusqlite::Params>(
    connection: &Connection,
    filter: &str,
    params: P,
) -> Result<Option<CompleteReceiptRow>, ClaimError> {
    let sql = format!(
        "SELECT command_id,idempotency_scope_bytes,idempotency_key,fingerprint,taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,new_version,admitted_event_id,started_event_id FROM taskrun_claim_receipts WHERE {filter}"
    );
    connection
        .query_row(&sql, params, |row| {
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
                row.get(11)?,
                row.get(12)?,
            ))
        })
        .optional()
        .map_err(|_| ClaimError::CorruptData)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receipt(
    taskrun: Vec<u8>,
    attempt: Vec<u8>,
    node: Vec<u8>,
    epoch: i64,
    fence: i64,
    expiry: i64,
    version: i64,
    admitted: Vec<u8>,
    started: Vec<u8>,
) -> Result<TaskRunClaimReceipt, ClaimError> {
    let node_uuid = uuid::Uuid::from_bytes(array16(node)?);
    let epoch = u64::try_from(epoch).map_err(|_| ClaimError::CorruptData)?;
    let fence = u64::try_from(fence).map_err(|_| ClaimError::CorruptData)?;
    let expiry = u64::try_from(expiry).map_err(|_| ClaimError::CorruptData)?;
    let version = u64::try_from(version).map_err(|_| ClaimError::CorruptData)?;
    let micros = i64::try_from(expiry)
        .ok()
        .and_then(|v| v.checked_mul(1000))
        .ok_or(ClaimError::CorruptData)?;
    Ok(TaskRunClaimReceipt {
        taskrun_id: TaskRunId::from_bytes(array16(taskrun)?),
        attempt_id: AttemptId::from_bytes(array16(attempt)?),
        node_id: ExecutionNodeId(node_uuid.to_string()),
        node_epoch: epoch,
        fence: TaskRunFence(fence),
        lease_expires_at: Timestamp::from_unix_micros(micros),
        new_version: version,
        admitted_event_id: EventId::from_bytes(array16(admitted)?),
        started_event_id: EventId::from_bytes(array16(started)?),
    })
}

fn array16(value: Vec<u8>) -> Result<[u8; 16], ClaimError> {
    value.try_into().map_err(|_| ClaimError::CorruptData)
}

pub(super) fn ensure_identity_free(
    tx: &rusqlite::Transaction<'_>,
    command_id: CommandId,
    scope: &[u8],
    key: &[u8],
) -> Result<(), ClaimError> {
    ensure_external_identity_free(tx, command_id, scope, key)
}

fn ensure_external_identity_free(
    connection: &Connection,
    command_id: CommandId,
    scope: &[u8],
    key: &[u8],
) -> Result<(), ClaimError> {
    let id = command_id.as_bytes();
    let command_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE command_id=?1) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=?1)",
        [id], |row| row.get(0),
    ).map_err(|_| ClaimError::CorruptData)?;
    let scope_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE idempotency_scope_bytes=?1 AND idempotency_key=?2)",
        rusqlite::params![scope, key], |row| row.get(0),
    ).map_err(|_| ClaimError::CorruptData)?;
    if command_exists || scope_exists {
        return Err(ClaimError::IdempotencyConflict);
    }
    Ok(())
}

pub(super) fn persist(
    tx: &rusqlite::Transaction<'_>,
    request: &TaskRunClaimRequest,
    scope: &[u8],
    node: [u8; 16],
    expiry: i64,
    receipt: &TaskRunClaimReceipt,
) -> Result<(), ClaimError> {
    let fence = i64::try_from(receipt.fence.0).map_err(|_| ClaimError::CorruptData)?;
    let epoch = i64::try_from(request.node_epoch).map_err(|_| ClaimError::NodeUnavailable)?;
    let version = i64::try_from(receipt.new_version).map_err(|_| ClaimError::CorruptData)?;
    tx.execute("INSERT INTO taskrun_assignments(taskrun_id,attempt_id,node_id,node_epoch,fence,capability_descriptor,lease_expires_at_ms,command_id,admitted_event_id,started_event_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![request.taskrun_id.as_bytes(),request.attempt_id.as_bytes(),node,epoch,fence,request.capability_descriptor,expiry,request.command_id.as_bytes(),request.admitted_event.event_id().as_bytes(),request.started_event.event_id().as_bytes()])
        .map_err(|_| ClaimError::CorruptData)?;
    tx.execute("INSERT INTO taskrun_assignment_occupations(taskrun_id,fence,attempt_id,node_id,node_epoch,lease_expires_at_ms,state,dispatch_intent) VALUES(?1,?2,?3,?4,?5,?6,'active','absent')",
        rusqlite::params![request.taskrun_id.as_bytes(),fence,request.attempt_id.as_bytes(),node,epoch,expiry])
        .map_err(|_| ClaimError::CorruptData)?;
    tx.execute("INSERT INTO taskrun_claim_receipts(command_id,idempotency_scope_bytes,idempotency_key,fingerprint,taskrun_id,attempt_id,node_id,node_epoch,fence,lease_expires_at_ms,new_version,admitted_event_id,started_event_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        rusqlite::params![request.command_id.as_bytes(),scope,request.idempotency_key.as_str().as_bytes(),request.command_fingerprint.as_bytes(),request.taskrun_id.as_bytes(),request.attempt_id.as_bytes(),node,epoch,fence,expiry,version,receipt.admitted_event_id.as_bytes(),receipt.started_event_id.as_bytes()])
        .map_err(|_| ClaimError::CorruptData)?;
    Ok(())
}
