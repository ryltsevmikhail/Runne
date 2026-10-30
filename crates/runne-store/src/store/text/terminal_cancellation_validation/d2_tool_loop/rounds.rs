use super::super::*;
use runne_application::ports::D2ToolLoopCancellationEvidence;
use rusqlite::{Connection, params};

type RoundRow = (
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

#[path = "rounds/continuation_identity.rs"]
mod continuation_identity;
#[path = "rounds/previous.rs"]
mod previous;
#[path = "rounds/rejected_admission.rs"]
mod rejected_admission;
#[path = "rounds/rejected_continuation.rs"]
mod rejected_continuation;

pub(crate) fn verify_cancelled_provider_rounds(
    tx: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    evidence: D2ToolLoopCancellationEvidence,
    original_claim_version: u64,
    cancel_version: u64,
) -> Result<(), CommitError> {
    let mut statement = tx
        .prepare(
            "SELECT b.round_index,b.attempt_id,b.node_id,b.node_epoch,
                    b.original_claim_version,b.current_taskrun_head,b.call_id,
                    b.prepared_digest,b.render_digest,b.profile_digest,
                    b.provider_idempotency_key,b.previous_attempt_id,b.previous_cycle_id,
                    b.previous_proposal_index,b.previous_semantic_digest,b.previous_result_digest,
                    a.taskrun_id,a.execution_attempt_id,a.prepared_digest,a.render_digest,
                    a.profile_digest,a.provider_idempotency_key,d.call_id,k.application_kind,
                    d.state,o.state
             FROM taskrun_provider_round_bindings b
             LEFT JOIN provider_execution_admissions a ON a.call_id=b.call_id
                  AND a.taskrun_id=b.taskrun_id AND a.execution_attempt_id=b.attempt_id
             LEFT JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
             LEFT JOIN provider_terminal_outbox o ON o.dispatch_attempt_id=d.attempt_id AND o.state=1
             LEFT JOIN provider_terminal_application_kinds k
               ON k.dispatch_attempt_id=o.dispatch_attempt_id AND k.outbox_id=o.outbox_id
             WHERE b.taskrun_id=?1 AND b.fence=?2 ORDER BY b.round_index",
        )
        .map_err(|_| integrity())?;
    let rows: Vec<RoundRow> = statement
        .query_map(
            params![taskrun_id.as_bytes(), evidence.fence as i64],
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
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                ))
            },
        )
        .map_err(|_| integrity())?
        .collect::<Result<_, _>>()
        .map_err(|_| integrity())?;
    if rows.is_empty() {
        let invocation_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations
                 WHERE taskrun_id=?1 AND attempt_id=?2)",
                params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
                |result| result.get(0),
            )
            .map_err(|_| integrity())?;
        let dispatch_intent_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3)",
                params![
                    taskrun_id.as_bytes(),
                    attempt_id.as_bytes(),
                    evidence.fence as i64
                ],
                |result| result.get(0),
            )
            .map_err(|_| integrity())?;
        let unbound_admission =
            rejected_continuation::has_unbound_admission(tx, taskrun_id, attempt_id)?;
        return if invocation_exists || dispatch_intent_exists || unbound_admission {
            Err(integrity())
        } else {
            Ok(())
        };
    }
    if rows.len()
        > crate::store::taskrun_tool_invocation::budget_policy::limits(tx, taskrun_id)
            .map_err(|_| integrity())?
            .1 as usize
            + 1
    {
        return Err(integrity());
    }
    let dispatch_intent_matches: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i
             JOIN taskrun_assignment_occupations o ON o.taskrun_id=i.taskrun_id
               AND o.fence=i.fence AND o.attempt_id=i.attempt_id AND o.node_id=i.node_id
               AND o.node_epoch=i.node_epoch
             WHERE i.taskrun_id=?1 AND i.attempt_id=?2 AND i.fence=?3
               AND i.node_id=?4 AND i.node_epoch=?5 AND i.state IN ('present','unknown')
               AND o.dispatch_intent=i.state)",
            params![
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                evidence.fence as i64,
                evidence.node_id.as_slice(),
                evidence.node_epoch as i64,
            ],
            |result| result.get(0),
        )
        .map_err(|_| integrity())?;
    if !dispatch_intent_matches {
        return Err(integrity());
    }
    let last_index = i64::try_from(rows.len() - 1).map_err(|_| integrity())?;
    for (expected_index, row) in rows.iter().enumerate() {
        let index = i64::try_from(expected_index).map_err(|_| integrity())?;
        if row.0 != index
            || row.1.as_slice() != attempt_id.as_bytes()
            || row.2.as_slice() != evidence.node_id
            || row.3 != evidence.node_epoch as i64
            || row.4 != original_claim_version as i64
            || row.5 <= original_claim_version as i64
            || row.5 > cancel_version as i64
        {
            return Err(integrity());
        }
        previous::verify(tx, taskrun_id, attempt_id, index, row)?;
        let has_admission = row.16.is_some();
        let admission_matches = match (
            row.16.as_deref(),
            row.17.as_deref(),
            row.18.as_deref(),
            row.19.as_deref(),
            row.20.as_deref(),
            row.21.as_deref(),
        ) {
            (
                Some(task),
                Some(attempt),
                Some(prepared),
                Some(render),
                Some(profile),
                Some(idem),
            ) => {
                task == taskrun_id.as_bytes()
                    && attempt == attempt_id.as_bytes()
                    && prepared == row.7
                    && render == row.8
                    && profile == row.9
                    && idem == row.10
            }
            (None, None, None, None, None, None) => false,
            _ => false,
        };
        if !has_admission || !admission_matches {
            return Err(integrity());
        }
        if let Some(dispatch_call) = row.22.as_deref() {
            if dispatch_call != row.6.as_slice()
                || (index != last_index
                    && (row.23 != Some(2) || row.24 != Some(4) || row.25 != Some(1)))
                || row.23.is_some_and(|kind| kind != 2)
                || (row.23.is_none() && index != last_index)
            {
                return Err(integrity());
            }
        } else if index != last_index {
            return Err(integrity());
        }
        let has_invocation: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND round_index=?3)",
                params![taskrun_id.as_bytes(), attempt_id.as_bytes(), index],
                |result| result.get(0),
            )
            .map_err(|_| integrity())?;
        if has_invocation
            && (!has_admission || row.23 != Some(2) || row.24 != Some(4) || row.25 != Some(1))
        {
            return Err(integrity());
        }
    }
    rejected_continuation::verify_if_present(
        tx,
        taskrun_id,
        attempt_id,
        evidence,
        original_claim_version,
        cancel_version,
        rows.len(),
    )?;
    Ok(())
}

fn integrity() -> CommitError {
    super::integrity()
}
