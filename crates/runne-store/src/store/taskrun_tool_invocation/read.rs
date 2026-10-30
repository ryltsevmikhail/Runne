use super::*;

mod codec;
use codec::*;
use runne_domain::id::{AttemptId, CycleId, TaskRunId};
use rusqlite::{OptionalExtension, params};

pub type ToolInvocationLookup = Option<ToolInvocationReceipt>;
type BudgetRefRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);
type ClaimMetadataRow = (
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
);

pub(super) fn get(
    store: &StoreTransaction,
    key: ToolInvocationKey,
) -> Result<ToolInvocationLookup, ToolInvocationStoreError> {
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    get_from_connection(&reader, key)
}

pub(super) fn load_budget_ref(
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
) -> Result<Option<runne_domain::reference::BudgetReservationRef>, ToolInvocationStoreError> {
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let row: Option<BudgetRefRow> = reader.query_row(
        "SELECT reservation_id,reservation_digest,attempt_id,fence FROM taskrun_tool_budgets WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if row.is_some() {
        budget_policy::limits(&reader, taskrun_id)?;
    }
    row.map(|(id, digest_bytes, attempt, _fence)| {
        Ok(runne_domain::reference::BudgetReservationRef {
            reservation_id: runne_domain::id::BudgetReservationId::from_bytes(fixed::<16>(id)?),
            taskrun_id,
            attempt_id: AttemptId::from_bytes(fixed::<16>(attempt)?),
            retry_ordinal: 0,
            reservation_digest: digest(digest_bytes)?,
        })
    })
    .transpose()
}

pub(super) fn get_from_connection(
    connection: &rusqlite::Connection,
    key: ToolInvocationKey,
) -> Result<ToolInvocationLookup, ToolInvocationStoreError> {
    let row: Option<Stored> = connection.query_row(
        "SELECT i.state,i.semantic_digest,i.result_digest,i.result_length,i.result_truncated,i.helper_receipt_digest,i.helper_receipt_bytes,i.receipt_key_id,i.receipt_key_version,i.receipt_runtime_authority_id,i.receipt_database_generation,i.receipt_nonce,i.receipt_plaintext_len,
         COALESCE((SELECT effects_used FROM taskrun_tool_budgets WHERE taskrun_id=?1),0),
         COALESCE((SELECT continuations_used FROM taskrun_tool_budgets WHERE taskrun_id=?1),0)
         FROM taskrun_tool_invocations i WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
        params![key.taskrun_id.as_bytes(), key.attempt_id.as_bytes(), key.cycle_id.as_bytes(), i64::from(key.proposal_index)],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?)),
    ).optional().map_err(|_| ToolInvocationStoreError::CorruptData)?;
    row.map(|row| decode_receipt(key, row)).transpose()
}

pub(super) fn load_record(
    connection: &rusqlite::Connection,
    key: ToolInvocationKey,
) -> Result<Option<ToolInvocationStoredRecord>, ToolInvocationStoreError> {
    let receipt = get_from_connection(connection, key)?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let mut binding = validate::load_binding_for_validation(connection, key)?;
    binding.canonical_arguments.clear();
    let claim: ClaimMetadataRow = connection.query_row(
        "SELECT claim_fence,claim_node_id,claim_node_epoch,updated_at,release_started,continuation_started,managed_area_identity,local_stop_state,empty_proof_identity,args_key_id,args_key_version,args_runtime_authority_id,args_database_generation,args_nonce FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
        params![key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?)),
    ).map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let (
        fence,
        node,
        epoch,
        updated_at,
        release_started,
        continuation_started,
        area,
        stop_state,
        proof,
        args_key,
        args_version,
        args_authority,
        args_generation,
        args_nonce,
    ) = claim;
    let claim_assignment = match (fence, node, epoch) {
        (None, None, None) => None,
        (Some(fence), Some(node), Some(epoch)) => Some(TaskRunAssignmentIdentity {
            taskrun_id: key.taskrun_id,
            attempt_id: key.attempt_id,
            node_id: runne_application::ports::ExecutionNodeId(node),
            node_epoch: u64::try_from(epoch).map_err(|_| ToolInvocationStoreError::CorruptData)?,
            fence: runne_application::ports::TaskRunFence(
                u64::try_from(fence).map_err(|_| ToolInvocationStoreError::CorruptData)?,
            ),
        }),
        _ => return Err(ToolInvocationStoreError::CorruptData),
    };
    let (
        Some(args_key),
        Some(args_version),
        Some(args_authority),
        Some(args_generation),
        Some(args_nonce),
    ) = (
        args_key,
        args_version,
        args_authority,
        args_generation,
        args_nonce,
    )
    else {
        return Err(ToolInvocationStoreError::CorruptData);
    };
    let arguments_payload = load_payload(
        connection,
        args_key,
        args_version,
        args_authority,
        args_generation,
        args_nonce,
        "canonical_arguments",
        "args_plaintext_len",
        "args_plaintext_digest",
        key,
    )?;
    let managed_area_identity = area
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)
        })
        .transpose()?;
    let empty_proof_identity = proof
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ToolInvocationStoreError::CorruptData)
        })
        .transpose()?;
    let local_stop_state = match stop_state {
        0 => LocalToolStopState::NotLaunched,
        1 => LocalToolStopState::Launched,
        2 => LocalToolStopState::ProvedEmpty,
        _ => return Err(ToolInvocationStoreError::CorruptData),
    };
    Ok(Some(ToolInvocationStoredRecord {
        binding,
        arguments_payload,
        receipt,
        updated_at,
        release_started: release_started != 0,
        continuation_started: continuation_started != 0,
        claim_assignment,
        managed_area_identity,
        local_stop_state,
        empty_proof_identity,
    }))
}

pub(super) fn list_for_taskrun(
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
) -> Result<Vec<ToolInvocationStoredRecord>, ToolInvocationStoreError> {
    let mut reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = reader
        .transaction()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let keys = {
        let mut statement=tx.prepare("SELECT attempt_id,cycle_id,proposal_index FROM taskrun_tool_invocations WHERE taskrun_id=?1 ORDER BY attempt_id,cycle_id,proposal_index LIMIT 33").map_err(|_|ToolInvocationStoreError::CorruptData)?;
        statement
            .query_map([taskrun_id.as_bytes()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| ToolInvocationStoreError::CorruptData)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ToolInvocationStoreError::CorruptData)?
    };
    if keys.len() > 32 {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    let mut records = Vec::with_capacity(keys.len());
    for (attempt, cycle, index) in keys {
        let key = ToolInvocationKey {
            taskrun_id,
            attempt_id: AttemptId::from_bytes(
                attempt
                    .try_into()
                    .map_err(|_| ToolInvocationStoreError::CorruptData)?,
            ),
            cycle_id: CycleId::from_bytes(
                cycle
                    .try_into()
                    .map_err(|_| ToolInvocationStoreError::CorruptData)?,
            ),
            proposal_index: u32::try_from(index)
                .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        };
        records.push(load_record(&tx, key)?.ok_or(ToolInvocationStoreError::CorruptData)?);
    }
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(records)
}

type Stored = (
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    i64,
    i64,
);
