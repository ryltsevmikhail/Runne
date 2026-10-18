use super::rejected_admission::{load_candidate, rejected_without_effect};
use super::*;
use rusqlite::params;

type Invocation = (
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    String,
);

pub(super) fn has_unbound_admission(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
) -> Result<bool, CommitError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
             WHERE a.taskrun_id=?1 AND a.execution_attempt_id=?2
               AND NOT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings b
                              WHERE b.call_id=a.call_id))",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| integrity())
}

pub(super) fn verify_if_present(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    evidence: D2ToolLoopCancellationEvidence,
    original_claim_version: u64,
    cancel_version: u64,
    bound_count: usize,
) -> Result<(), CommitError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_execution_admissions a
             WHERE a.taskrun_id=?1 AND a.execution_attempt_id=?2
               AND NOT EXISTS(SELECT 1 FROM taskrun_provider_round_bindings b
                              WHERE b.call_id=a.call_id)",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| integrity())?;
    if count == 0 {
        return Ok(());
    }
    if count != 1 || !(1..=2).contains(&bound_count) {
        return Err(integrity());
    }
    super::rejected_admission::verify_origin_claim(
        connection,
        taskrun_id,
        attempt_id,
        evidence,
        original_claim_version,
    )?;
    let (command, conversation, principal, runtime) =
        super::continuation_identity::durable_generation_identity(
            connection,
            taskrun_id,
            attempt_id,
            cancel_version,
            original_claim_version,
        )?;
    let round = u32::try_from(bound_count).map_err(|_| integrity())?;
    let invocation = previous_invocation(connection, taskrun_id, attempt_id, round, evidence)?;
    let (cycle, pre_failure_head) = super::continuation_identity::validate_failure_suffix(
        connection,
        taskrun_id,
        attempt_id,
        cancel_version,
        original_claim_version,
        &invocation.0,
        invocation.1,
        &invocation.3,
    )?;
    let (proposal, semantic, result) = (
        u32::try_from(invocation.1).map_err(|_| integrity())?,
        invocation.2.as_slice(),
        invocation.3.as_slice(),
    );
    let call = super::continuation_identity::round_call_id(
        &command,
        taskrun_id.as_bytes(),
        attempt_id.as_bytes(),
        pre_failure_head,
        round,
        super::continuation_identity::PreviousResult {
            attempt_id: attempt_id.as_bytes(),
            cycle_id: &cycle,
            proposal_index: proposal,
            semantic_digest: semantic,
            result_digest: result,
        },
    )
    .ok_or_else(integrity)?;
    let candidate = load_candidate(
        connection,
        taskrun_id,
        attempt_id,
        evidence,
        &call,
        &conversation,
        &principal,
        &runtime,
    )?
    .ok_or_else(integrity)?;
    let digest_version = u8::try_from(candidate.digest_version).map_err(|_| integrity())?;
    let input_tokens = u64::try_from(candidate.input_tokens).map_err(|_| integrity())?;
    let output_tokens = u64::try_from(candidate.output_tokens).map_err(|_| integrity())?;
    let max_cost = u64::try_from(candidate.max_cost).map_err(|_| integrity())?;
    let expected_semantic = super::continuation_identity::semantic_digest(
        &super::continuation_identity::SemanticFields {
            principal: &candidate.principal,
            conversation: &candidate.conversation,
            taskrun: &candidate.taskrun,
            attempt: &candidate.attempt,
            call: &candidate.call,
            digest_version,
            prepared: &candidate.prepared,
            render: &candidate.render,
            profile: &candidate.profile,
            pricing: &candidate.pricing,
            input_tokens,
            output_tokens,
            max_cost,
            currency: &candidate.currency,
            idempotency_key: &candidate.idem,
        },
    )
    .ok_or_else(integrity)?;
    if candidate.semantic.as_slice() != expected_semantic.as_slice()
        || candidate.call.as_slice() != call.as_slice()
        || candidate.idem != super::rejected_admission::round_idempotency_key(&call)
        || !rejected_without_effect(&candidate)
    {
        return Err(integrity());
    }
    verify_budget(connection, taskrun_id, attempt_id, evidence, round)?;
    Ok(())
}

fn previous_invocation(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    round: u32,
    evidence: D2ToolLoopCancellationEvidence,
) -> Result<Invocation, CommitError> {
    let mut statement = connection
        .prepare(
        "SELECT cycle_id,proposal_index,semantic_digest,result_digest,round_index,
                result_truncated,release_started,local_stop_state,managed_area_identity,empty_proof_identity,
                continuation_started,state
         FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND round_index=?3",
        )
        .map_err(|_| integrity())?;
    let rows = statement
        .query_map(
            params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                i64::from(round - 1)
            ],
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
                ))
            },
        )
        .map_err(|_| integrity())?
        .collect::<Result<Vec<Invocation>, _>>()
        .map_err(|_| integrity())?;
    let [row] = rows.as_slice() else {
        return Err(integrity());
    };
    let area_matches =
        matches!((&row.8, &row.9), (Some(area), Some(proof)) if !area.is_empty() && area == proof);
    let claim: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4 AND claim_fence=?5 AND claim_node_id=?6 AND claim_node_epoch=?7)",
        params![taskrun_id.as_bytes(),attempt_id.as_bytes(),row.0,row.1,evidence.fence as i64,uuid::Uuid::from_bytes(evidence.node_id).to_string(),evidence.node_epoch as i64], |r| r.get(0),
    ).map_err(|_| integrity())?;
    if row.2.len() != 32
        || row.3.len() != 32
        || row.1 < 0
        || row.4 != i64::from(round - 1)
        || row.5 != 0
        || row.6 != 1
        || row.7 != 2
        || row.10 != 0
        || row.11 != "result"
        || !area_matches
        || !claim
    {
        return Err(integrity());
    }
    Ok((
        row.0.clone(),
        row.1,
        row.2.clone(),
        row.3.clone(),
        row.4,
        row.5,
        row.6,
        row.7,
        row.8.clone(),
        row.9.clone(),
        row.10,
        row.11.clone(),
    ))
}

fn verify_budget(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    evidence: D2ToolLoopCancellationEvidence,
    round: u32,
) -> Result<(), CommitError> {
    let valid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2
          AND fence=?3 AND node_id=?4 AND node_epoch=?5 AND policy_revision='d2-safe-tool-loop-budget-v1'
          AND effects_limit=2 AND continuations_limit=2 AND effects_used=?6 AND continuations_used=?7)",
        params![taskrun_id.as_bytes(),attempt_id.as_bytes(),evidence.fence as i64,
            uuid::Uuid::from_bytes(evidence.node_id).to_string(),evidence.node_epoch as i64,
            i64::from(round),i64::from(round-1)], |r| r.get(0),
    ).map_err(|_| integrity())?;
    if valid { Ok(()) } else { Err(integrity()) }
}

fn integrity() -> CommitError {
    super::integrity()
}
