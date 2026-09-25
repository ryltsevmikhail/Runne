use super::*;
use runne_application::ports::{
    ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunClaimError as ClaimError,
    TaskRunClaimLookup, TaskRunClaimLookupResult, TaskRunClaimPort, TaskRunClaimReceipt,
    TaskRunClaimRequest, TaskRunClaimResult, TaskRunFence,
};
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use std::str::FromStr;

pub(crate) struct ReleaseEventMetadata<'a> {
    pub command_id: CommandId,
    pub idempotency_key: &'a [u8],
}

mod events;
mod receipts;
mod stream_integrity;
pub(super) mod stream_validate;
mod write;

type ClaimAuthorityRow = (
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

pub(super) fn verify_active_assignment(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
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
        || receipt.node_id.0 != identity.node_id.0
        || receipt.node_epoch != identity.node_epoch
        || receipt.fence != identity.fence
    {
        return Err(ClaimError::CorruptData);
    }
    let command = CommandId::from_bytes(command.try_into().map_err(|_| ClaimError::CorruptData)?);
    receipts::verify_assignment(connection, &receipt, command)?;
    stream_integrity::verify_current_claim_stream(connection, &receipt, command, &key)
}

pub(crate) fn verify_released_stream(
    connection: &Connection,
    receipt: &TaskRunClaimReceipt,
    command: CommandId,
    key: &[u8],
    event: EventId,
    version: u64,
    release: ReleaseEventMetadata<'_>,
) -> Result<(), ClaimError> {
    stream_integrity::verify_released_stream(
        connection, receipt, command, key, event, version, release,
    )
}

const MAX_CLAIM_LEASE_MS: u64 = 300_000;
const LINUX_CAPABILITY_DESCRIPTOR: &str = "linux-executor-v1";

impl TaskRunClaimPort for StoreTransaction {
    fn lookup_task_run_claim(
        &self,
        lookup: TaskRunClaimLookup,
    ) -> Result<TaskRunClaimLookupResult, ClaimError> {
        let scope = encode_scope(&lookup.idempotency_scope)?;
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| ClaimError::Unavailable)?;
        receipts::lookup(
            &connection,
            lookup.command_id,
            lookup.idempotency_key.as_str().as_bytes(),
            &scope,
            lookup.command_fingerprint.as_bytes(),
        )
    }

    fn claim_task_run(
        &self,
        request: TaskRunClaimRequest,
    ) -> Result<TaskRunClaimResult, ClaimError> {
        let scope = encode_scope(&request.idempotency_scope)?;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| ClaimError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ClaimError::Unavailable)?;
        if let Some(receipt) = receipts::lookup_tx(
            &tx,
            request.command_id,
            request.idempotency_key.as_str().as_bytes(),
            &scope,
            request.command_fingerprint.as_bytes(),
        )? {
            tx.commit().map_err(|_| ClaimError::Unavailable)?;
            return Ok(TaskRunClaimResult::Duplicate(receipt));
        }
        receipts::ensure_identity_free(
            &tx,
            request.command_id,
            &scope,
            request.idempotency_key.as_str().as_bytes(),
        )?;
        validate_request(&request)?;
        let node_id = parse_node_id(&request.node_id)?;
        let current =
            events::validate_queued_stream(&tx, request.taskrun_id, request.expected_version)?;
        let previous_id: Vec<u8> = tx.query_row(
            "SELECT last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [request.taskrun_id.as_bytes()], |row| row.get(0),
        ).map_err(|_| ClaimError::CorruptData)?;
        if request
            .admitted_event
            .causation_id()
            .map(|id| id.as_bytes().as_slice())
            != Some(previous_id.as_slice())
        {
            return Err(ClaimError::CorruptData);
        }
        let now_ms = events::database_now_ms(&tx)?;
        write::ensure_live_node(&tx, node_id, &request, now_ms)?;
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE node_id=?1 AND state='active'",
                rusqlite::params![node_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ClaimError::CorruptData)?;
        let capacity: i64 = tx
            .query_row(
                "SELECT capacity FROM execution_nodes WHERE node_id=?1",
                [node_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ClaimError::CorruptData)?;
        if active >= capacity {
            return Err(ClaimError::NodeUnavailable);
        }
        let fence = write::allocate_fence(&tx, request.taskrun_id)?;
        let expires = now_ms
            .checked_add(
                i64::try_from(request.lease_duration_ms)
                    .map_err(|_| ClaimError::NodeUnavailable)?,
            )
            .ok_or(ClaimError::NodeUnavailable)?;
        let event_time_us = now_ms.checked_mul(1000).ok_or(ClaimError::CorruptData)?;
        write::append_claim_events(self, &tx, &request, current, event_time_us)?;
        let receipt = TaskRunClaimReceipt {
            taskrun_id: request.taskrun_id,
            attempt_id: request.attempt_id,
            node_id: request.node_id.clone(),
            node_epoch: request.node_epoch,
            fence: TaskRunFence(fence),
            lease_expires_at: Timestamp::from_unix_micros(
                expires
                    .checked_mul(1000)
                    .ok_or(ClaimError::NodeUnavailable)?,
            ),
            new_version: request
                .expected_version
                .checked_add(2)
                .ok_or(ClaimError::CorruptData)?,
            admitted_event_id: *request.admitted_event.event_id(),
            started_event_id: *request.started_event.event_id(),
        };
        receipts::persist(&tx, &request, &scope, node_id, expires, &receipt)?;
        tx.commit().map_err(|_| ClaimError::Unavailable)?;
        Ok(TaskRunClaimResult::Committed(receipt))
    }
}

fn encode_scope(scope: &IdempotencyScope) -> Result<Vec<u8>, ClaimError> {
    if scope.operation != OperationTag::TaskRunClaim
        || !matches!(
            scope.aggregate_scope,
            AggregateScope::ExistingTaskRun { .. }
        )
    {
        return Err(ClaimError::IdempotencyConflict);
    }
    IdempotencyScopeCodec
        .encode(scope)
        .map_err(|_| ClaimError::CorruptData)
}

fn validate_request(request: &TaskRunClaimRequest) -> Result<(), ClaimError> {
    if request.capability_descriptor != LINUX_CAPABILITY_DESCRIPTOR {
        return Err(ClaimError::CapabilityMismatch);
    }
    if request.idempotency_scope.aggregate_scope
        != (AggregateScope::ExistingTaskRun {
            taskrun_id: request.taskrun_id,
        })
        || request.lease_duration_ms == 0
        || request.lease_duration_ms > MAX_CLAIM_LEASE_MS
        || request.admitted_event.aggregate_id() != &AggregateId::TaskRun(request.taskrun_id)
        || request.started_event.aggregate_id() != &AggregateId::TaskRun(request.taskrun_id)
        || request.admitted_event.command_id() != &request.command_id
        || request.started_event.command_id() != &request.command_id
        || request.admitted_event.idempotency_key() != &request.idempotency_key
        || request.started_event.idempotency_key() != &request.idempotency_key
        || request.started_event.causation_id() != Some(request.admitted_event.event_id())
        || request.admitted_event.payload() != &TaskRunEvent::TaskRunAdmitted
        || request.started_event.payload()
            != &(TaskRunEvent::AttemptStarted {
                attempt_id: request.attempt_id,
            })
    {
        return Err(ClaimError::CorruptData);
    }
    Ok(())
}

fn parse_node_id(id: &ExecutionNodeId) -> Result<[u8; 16], ClaimError> {
    let parsed = uuid::Uuid::from_str(&id.0).map_err(|_| ClaimError::NodeUnavailable)?;
    if parsed.is_nil() || parsed.to_string() != id.0 {
        return Err(ClaimError::NodeUnavailable);
    }
    Ok(*parsed.as_bytes())
}
