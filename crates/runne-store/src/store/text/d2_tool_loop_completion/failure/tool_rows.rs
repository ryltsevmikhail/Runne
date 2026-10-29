use super::super::*;
use crate::store::taskrun_tool_invocation::ToolInvocationKey;
use runne_application::ports::TaskRunAssignmentIdentity;
use rusqlite::params;

type Row = (
    Vec<u8>,
    i64,
    Vec<u8>,
    String,
    Option<i64>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

pub(super) fn verify_budget_assignment(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    assignment: &TaskRunAssignmentIdentity,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    crate::store::taskrun_tool_invocation::budget_policy::verify_origin_policy(tx, taskrun_id)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let node = uuid::Uuid::parse_str(&assignment.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let exact: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets b
             JOIN taskrun_assignments a ON a.taskrun_id=b.taskrun_id
               AND a.fence=b.fence AND a.attempt_id=b.attempt_id
             WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND b.fence=?3
               AND b.node_id=?4 AND b.node_epoch=?5
               AND b.policy_revision IN ('d2-safe-tool-loop-budget-v1','coding-tool-loop-budget-v1')
               AND a.node_id=?6 AND a.node_epoch=?5)",
            params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                assignment.fence.0 as i64,
                node.to_string(),
                assignment.node_epoch as i64,
                node.as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !exact {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

/// Accepts only a truly absent budget or the exact immutable claim-bound row.
/// A present row with a corrupt or stale binding must never look like absence.
pub(super) fn verify_budget_assignment_if_present(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    assignment: &TaskRunAssignmentIdentity,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1)",
            params![taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if exists {
        verify_budget_assignment(tx, taskrun_id, attempt_id, assignment)?;
    } else {
        let invocations: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2",
                params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if invocations != 0 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    Ok(())
}

pub(super) fn verify_safe_tool_stop(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    cycle_id: runne_domain::id::CycleId,
    assignment: &TaskRunAssignmentIdentity,
    require_result: bool,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let mut stmt = tx
        .prepare(
            "SELECT cycle_id,proposal_index,semantic_digest,state,result_truncated,
        local_stop_state,managed_area_identity,empty_proof_identity,release_started,
        claim_fence,claim_node_id,claim_node_epoch,result_digest,receipt_nonce FROM taskrun_tool_invocations
        WHERE taskrun_id=?1 AND attempt_id=?2 ORDER BY cycle_id,proposal_index",
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let rows = stmt
        .query_map(
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
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        .collect::<Result<Vec<Row>, _>>()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    drop(stmt);
    let mut results = 0usize;
    for row in &rows {
        if row.0.as_slice() != cycle_id.as_bytes() || row.1 < 0 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let index =
            u32::try_from(row.1).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let digest: [u8; 32] = row
            .2
            .as_slice()
            .try_into()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let key = ToolInvocationKey {
            taskrun_id,
            attempt_id,
            cycle_id,
            proposal_index: index,
        };
        let semantic = runne_domain::id::IntegrityDigest::from_bytes(digest);
        let claimed = matches!(
            row.3.as_str(),
            "claimed" | "uncertain" | "result" | "cancelled" | "audit_only"
        );
        let tuple_ok = if claimed {
            row.9 == Some(assignment.fence.0 as i64)
                && row.10.as_deref() == Some(assignment.node_id.0.as_str())
                && row.11 == Some(assignment.node_epoch as i64)
        } else {
            row.9.is_none() && row.10.is_none() && row.11.is_none()
        };
        let proof_ok = if let (Some(area), Some(proof)) = (&row.6, &row.7) {
            area == proof
                && area.len() == 100
                && runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(area)
                    .is_ok()
                && area[52..68] == *taskrun_id.as_bytes()
                && area[68..84] == *attempt_id.as_bytes()
                && area[84..100] == key.managed_area_nonce(semantic)
        } else {
            false
        };
        let safe = match row.3.as_str() {
            "result" => {
                results += 1;
                row.5 == 2 && proof_ok && row.4 == Some(0)
            }
            "uncertain" | "audit_only" => row.5 == 2 && proof_ok,
            "proposed" | "approved" | "denied" => {
                !claimed && row.8 == 0 && row.5 == 0 && row.6.is_none() && row.7.is_none()
            }
            "claimed" => {
                row.8 == 0
                    && row.5 == 0
                    && row.6.is_none()
                    && row.7.is_none()
                    && row.12.is_none()
                    && row.13.is_none()
            }
            _ => false,
        };
        if !tuple_ok || !safe {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    if rows.is_empty() {
        // A provider proposal can be malformed or out of scope after a fully
        // admitted, journaled round.  That is enough to stop this local
        // workflow: no native effect can run without a persisted invocation
        // row.  The caller has already verified the exact round/admission
        // chain with `verify_d2_cancelled_provider_rounds`.
        if require_result || !verify_no_invocations(tx, taskrun_id, attempt_id)? {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    } else if require_result && results == 0 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

fn verify_no_invocations(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
) -> Result<bool, CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    Ok(count == 0)
}

#[cfg(test)]
#[path = "tool_rows/tests.rs"]
mod tests;
