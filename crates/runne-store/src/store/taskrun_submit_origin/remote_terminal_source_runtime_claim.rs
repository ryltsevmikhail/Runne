use super::*;
use crate::codec::StoreCodec;
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence};
use runne_domain::event::EventEnvelope;
use runne_domain::task_run::TaskRunEvent;
use rusqlite::OptionalExtension;

/// Permit the daemon's runtime-owned claim actor only when its exact durable
/// claim receipt, assignment history, D2 budget, and round bindings agree.
pub(super) struct RuntimeClaimContext<'a> {
    pub(super) taskrun_id: TaskRunId,
    pub(super) attempt_id: AttemptId,
    pub(super) started_version: u64,
    pub(super) admitted: &'a EventEnvelope<TaskRunEvent>,
    pub(super) started: &'a EventEnvelope<TaskRunEvent>,
    pub(super) authority: &'a RuntimeAuthorityId,
    pub(super) profile_id: &'a str,
}

type ClaimReceiptRow = (Vec<u8>, Vec<u8>, i64, i64, i64);

pub(super) fn verify_runtime_claim_actor(
    connection: &Connection,
    context: RuntimeClaimContext<'_>,
) -> Result<bool, CommitError> {
    let RuntimeClaimContext {
        taskrun_id,
        attempt_id,
        started_version,
        admitted,
        started,
        authority,
        profile_id,
    } = context;
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let row: Option<ClaimReceiptRow> = connection
        .query_row(
            "SELECT idempotency_scope_bytes,node_id,node_epoch,fence,new_version
             FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND new_version=?3
               AND command_id=?4 AND idempotency_key=?5
               AND admitted_event_id=?6 AND started_event_id=?7",
            rusqlite::params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                i64::try_from(started_version).map_err(|_| invalid())?,
                started.command_id().as_bytes(),
                started.idempotency_key().as_str().as_bytes(),
                admitted.event_id().as_bytes(),
                started.event_id().as_bytes(),
            ],
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
        .map_err(|_| invalid())?;
    let Some((scope_bytes, node_bytes, epoch, fence, version)) = row else {
        return Ok(false);
    };
    let scope = crate::codec::IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| invalid())?;
    if !support::runtime_claim_scope_matches(&scope, authority, taskrun_id, started.actor()) {
        return Ok(false);
    }
    let node = uuid::Uuid::from_slice(&node_bytes).map_err(|_| invalid())?;
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id,
        node_id: ExecutionNodeId(node.to_string()),
        node_epoch: u64::try_from(epoch).map_err(|_| invalid())?,
        fence: TaskRunFence(u64::try_from(fence).map_err(|_| invalid())?),
    };
    if u64::try_from(version).map_err(|_| invalid())? != started_version
        || crate::store::taskrun_claim::verify_assignment_history(connection, &identity).is_err()
        || profile_id != "runne-linux-agent-tools-v1"
    {
        return Ok(false);
    }
    verify_d2_round_budget(connection, &identity)
}

fn verify_d2_round_budget(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
) -> Result<bool, CommitError> {
    let invalid = || storage_failure(StorageFailureKind::IntegrityViolation);
    let node = uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| invalid())?;
    let binding: Option<(i64, i64, i64, i64, i64)> = connection
        .query_row(
            "SELECT b.effects_limit,b.continuations_limit,b.effects_used,b.continuations_used,
                    (SELECT count(*) FROM taskrun_provider_round_bindings r
                     WHERE r.taskrun_id=b.taskrun_id AND r.attempt_id=b.attempt_id
                       AND r.fence=b.fence AND r.node_id=?4 AND r.node_epoch=?5)
             FROM taskrun_tool_budgets b
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND b.fence=?3
               AND b.node_id=?6 AND b.node_epoch=?5 AND b.policy_revision='d2-safe-tool-loop-budget-v1'",
            rusqlite::params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes(),
                i64::try_from(identity.fence.0).map_err(|_| invalid())?,
                node.as_bytes(),
                i64::try_from(identity.node_epoch).map_err(|_| invalid())?,
                identity.node_id.0,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    let Some((effects_limit, continuations_limit, effects_used, continuations_used, rounds)) =
        binding
    else {
        return Ok(false);
    };
    Ok(effects_limit == 2
        && continuations_limit == 2
        && (0..=2).contains(&effects_used)
        && (0..=2).contains(&continuations_used)
        && (1..=3).contains(&rounds))
}
