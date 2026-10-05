use super::super::super::parse_helpers::storage_failure;
use super::super::super::test_support_diagnostics as diagnostics;
use super::super::super::*;
use runne_application::ports::{
    D2ToolLoopCancellationEvidence, RejectTextGenerationAfterCancellationCommit,
};
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::{Transaction, params};

#[path = "d2_tool_loop/rounds.rs"]
pub(crate) mod rounds;

type InvocationRow = (
    String,
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Vec<u8>,
    i64,
    Vec<u8>,
);

pub(super) fn verify(
    tx: &Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
    evidence: D2ToolLoopCancellationEvidence,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let taskrun_id = payload.receipt.taskrun_id;
    let attempt = payload.receipt.attempt_id;
    if evidence.cancellation_taskrun_version <= payload.expected_started_taskrun_version
        || payload.receipt.taskrun_version
            != evidence
                .cancellation_taskrun_version
                .checked_add(1)
                .ok_or_else(integrity)?
    {
        diagnostics::record("cancel.d2.version");
        return Err(integrity());
    }
    let stream = super::super::super::taskrun_claim::stream_validate::verify_stream(
        tx,
        taskrun_id,
        Some(evidence.cancellation_taskrun_version),
    )
    .map_err(|_| integrity())?;
    let task = TaskRun::replay(&stream.events).map_err(|_| integrity())?;
    if task.state() != TaskRunState::Cancelling
        || stream
            .events
            .last()
            .is_none_or(|event| event.payload() != &TaskRunEvent::CancellationRequested)
    {
        diagnostics::record("cancel.d2.canonical_taskrun");
        return Err(integrity());
    }
    let assignment: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_claim_receipts c
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=c.taskrun_id AND o.fence=c.fence
                AND o.attempt_id=c.attempt_id AND o.node_id=c.node_id AND o.node_epoch=c.node_epoch
             JOIN taskrun_assignments a ON a.taskrun_id=c.taskrun_id AND a.fence=c.fence
                AND a.attempt_id=c.attempt_id AND a.node_id=c.node_id AND a.node_epoch=c.node_epoch
             WHERE c.taskrun_id=?1 AND c.attempt_id=?2 AND c.fence=?3 AND c.node_id=?4
               AND c.node_epoch=?5 AND c.new_version=?6 AND o.state='active')",
            params![
                taskrun_id.as_bytes(),
                attempt.as_bytes(),
                evidence.fence as i64,
                evidence.node_id.as_slice(),
                evidence.node_epoch as i64,
                payload.expected_started_taskrun_version as i64,
            ],
            |row| row.get(0),
        )
        .map_err(|_| integrity())?;
    if !assignment {
        diagnostics::record("cancel.d2.assignment");
        return Err(integrity());
    }
    let budget_rows: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            params![taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| integrity())?;
    if budget_rows > 0 {
        let exact_budget: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2
               AND fence=?3 AND node_id=?4 AND node_epoch=?5
               AND policy_revision='d2-safe-tool-loop-budget-v1')",
            params![taskrun_id.as_bytes(), attempt.as_bytes(), evidence.fence as i64,
                uuid::Uuid::from_bytes(evidence.node_id).to_string(), evidence.node_epoch as i64],
            |row| row.get(0),
        ).map_err(|_| integrity())?;
        if !exact_budget {
            diagnostics::record("cancel.d2.budget");
            return Err(integrity());
        }
    }
    super::super::super::taskrun_submit_origin::verify_submitted_v2_origin(
        tx, taskrun_id, authority,
    )
    .map_err(|_| integrity())?
    .ok_or_else(|| {
        diagnostics::record("cancel.d2.origin");
        integrity()
    })?;
    if verify_invocations(tx, taskrun_id, attempt, evidence).is_err() {
        diagnostics::record("cancel.d2.invocations");
        return Err(integrity());
    }
    if rounds::verify_cancelled_provider_rounds(
        tx,
        taskrun_id,
        attempt,
        evidence,
        payload.expected_started_taskrun_version,
        evidence.cancellation_taskrun_version,
    )
    .is_err()
    {
        diagnostics::record("cancel.d2.rounds");
        return Err(integrity());
    }
    Ok(())
}

fn verify_invocations(
    tx: &Transaction<'_>,
    taskrun_id: TaskRunId,
    attempt: AttemptId,
    evidence: D2ToolLoopCancellationEvidence,
) -> Result<(), CommitError> {
    let mut statement = tx
        .prepare(
            "SELECT state,claim_fence,claim_node_id,claim_node_epoch,release_started,
                    local_stop_state,managed_area_identity,empty_proof_identity,
                    result_digest,result_truncated,cycle_id,proposal_index,semantic_digest
             FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2",
        )
        .map_err(|_| integrity())?;
    let rows: Vec<InvocationRow> = statement
        .query_map(params![taskrun_id.as_bytes(), attempt.as_bytes()], |row| {
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
        .map_err(|_| integrity())?
        .collect::<Result<_, _>>()
        .map_err(|_| integrity())?;
    if rows.len() > 2 {
        return Err(integrity());
    }
    for (
        state,
        fence,
        node,
        epoch,
        release_intent,
        stopped,
        area,
        proof,
        digest,
        truncated,
        cycle,
        index,
        semantic,
    ) in rows
    {
        let claim_matches = match (fence, node.as_ref(), epoch) {
            (None, None, None) if matches!(state.as_str(), "proposed" | "approved" | "denied") => {
                true
            }
            (Some(fence), Some(node), Some(epoch)) => {
                fence == evidence.fence as i64
                    && node.as_str() == uuid::Uuid::from_bytes(evidence.node_id).to_string()
                    && epoch == evidence.node_epoch as i64
            }
            _ => false,
        };
        let area_safe = match (stopped, area.as_ref(), proof.as_ref()) {
            (0, None, None) => release_intent == 0,
            (2, Some(area), Some(proof)) => area == proof,
            _ => false,
        };
        let area_binding_matches = area.as_ref().is_none_or(|bytes| {
            let Ok(identity) =
                runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(bytes)
            else {
                return false;
            };
            let encoded = identity.to_bytes();
            let Ok(cycle_bytes) = <[u8; 16]>::try_from(cycle.as_slice()) else {
                return false;
            };
            let Ok(semantic_bytes) = <[u8; 32]>::try_from(semantic.as_slice()) else {
                return false;
            };
            let key = crate::store::taskrun_tool_invocation::ToolInvocationKey {
                taskrun_id,
                attempt_id: attempt,
                cycle_id: runne_domain::id::CycleId::from_bytes(cycle_bytes),
                proposal_index: u32::try_from(index).unwrap_or(u32::MAX),
            };
            encoded[52..68] == *taskrun_id.as_bytes()
                && encoded[68..84] == *attempt.as_bytes()
                && encoded[84..100]
                    == key.managed_area_nonce(IntegrityDigest::from_bytes(semantic_bytes))
        });
        let known = match state.as_str() {
            "proposed" | "approved" | "denied" => {
                stopped == 0 && area.is_none() && release_intent == 0
            }
            "claimed" => area_safe,
            "uncertain" | "audit_only" => stopped == 2 && area_safe,
            "result" => stopped == 2 && area_safe && digest.is_some() && truncated == Some(0),
            "cancelled" => area_safe,
            _ => false,
        };
        if !claim_matches || !known || !area_binding_matches {
            return Err(integrity());
        }
    }
    Ok(())
}

fn integrity() -> CommitError {
    storage_failure(StorageFailureKind::IntegrityViolation)
}
