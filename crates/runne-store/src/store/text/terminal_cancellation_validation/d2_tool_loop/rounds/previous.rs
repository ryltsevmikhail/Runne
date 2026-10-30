use super::*;
pub(super) fn verify(
    tx: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    index: i64,
    row: &RoundRow,
) -> Result<(), CommitError> {
    let previous = (
        row.11.as_deref(),
        row.12.as_deref(),
        row.13,
        row.14.as_deref(),
        row.15.as_deref(),
    );
    if index == 0 {
        if previous != (None, None, None, None, None) {
            return Err(integrity());
        }
    } else {
        let (
            Some(prev_attempt),
            Some(prev_cycle),
            Some(prev_index),
            Some(prev_semantic),
            Some(prev_result),
        ) = previous
        else {
            return Err(integrity());
        };
        if prev_attempt != attempt_id.as_bytes()
            || (Some(prev_index) != index.checked_sub(1)
                && !crate::store::taskrun_tool_invocation::budget_policy::coding_origin(
                    tx, taskrun_id,
                )
                .map_err(|_| integrity())?)
        {
            return Err(integrity());
        }
        let linked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations
                     WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4
                       AND semantic_digest=?5 AND state='result' AND result_digest=?6
                       AND result_truncated=0 AND continuation_started=1 AND round_index=?7
                       AND local_stop_state=2 AND managed_area_identity=empty_proof_identity)",
                params![
                    taskrun_id.as_bytes(),
                    prev_attempt,
                    prev_cycle,
                    prev_index,
                    prev_semantic,
                    prev_result,
                    index - 1
                ],
                |result| result.get(0),
            )
            .map_err(|_| integrity())?;
        if !linked {
            return Err(integrity());
        }
    }
    Ok(())
}
