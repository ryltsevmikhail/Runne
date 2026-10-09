fn validate_d2_round(
    tx: &rusqlite::Transaction<'_>,
    request: &BindPreparedTaskRunProviderRoundEffect,
    already_bound: bool,
) -> Result<(), Error> {
    validate_prepared_request(&request.prepared)?;
    if request.round_index > 2 {
        return Err(Error::NotPrepared);
    }
    if (request.round_index == 0) != request.previous_tool_result.is_none() {
        return Err(Error::IdempotencyConflict);
    }
    let node = binding_node_id(&request.identity)?;
    let now = binding_now_ms(tx)?;
    let occupation = super::taskrun_assignment::exact_occupation(tx, &request.identity, node)
        .map_err(map_assignment_error)?;
    super::taskrun_assignment::verify_current_claim(tx, &request.identity)
        .map_err(map_assignment_error)?;
    super::taskrun_assignment::ensure_live_local_node(tx, &request.identity, node, now)
        .map_err(map_assignment_error)?;
    if occupation.3 <= now {
        return Err(Error::LeaseExpired);
    }
    if occupation.4 != "active" {
        return Err(Error::StaleAssignment);
    }
    let claim: i64 = tx
        .query_row(
            "SELECT new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3",
            rusqlite::params![request.identity.taskrun_id.as_bytes(),request.identity.fence.0 as i64,request.identity.attempt_id.as_bytes()],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?
        .ok_or(Error::StaleAssignment)?;
    let head: i64 = tx
        .query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [request.identity.taskrun_id.as_bytes()],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Error::CorruptData)?
        .ok_or(Error::StaleVersion)?;
    if claim != request.original_claim_version as i64 || head != request.current_taskrun_head as i64
    {
        return Err(Error::StaleVersion);
    }
    let stream = super::taskrun_claim::stream_validate::verify_stream(
        tx,
        request.identity.taskrun_id,
        Some(request.current_taskrun_head),
    )
    .map_err(|_| Error::StaleVersion)?;
    let task =
        runne_domain::task_run::TaskRun::replay(&stream.events).map_err(|_| Error::CorruptData)?;
    if task.state() != runne_domain::task_run::TaskRunState::Running
        || task.active_attempt() != Some(&request.identity.attempt_id)
    {
        return Err(Error::StaleAssignment);
    }
    if let Some(previous) = request.previous_tool_result {
        let expected_started = i64::from(already_bound);
        let expected_budget = (request.round_index - 1 + u32::from(already_bound)) as i64;
        let valid: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations i JOIN taskrun_tool_budgets b ON b.taskrun_id=i.taskrun_id WHERE i.taskrun_id=?1 AND i.attempt_id=?2 AND i.cycle_id=?3 AND i.proposal_index=?4 AND i.semantic_digest=?5 AND i.result_digest=?6 AND i.result_truncated=0 AND i.state='result' AND i.release_started=1 AND i.local_stop_state=2 AND i.continuation_started=?10 AND b.attempt_id=?2 AND b.fence=?7 AND i.round_index=?8 AND b.continuations_used=?9)",
                rusqlite::params![request.identity.taskrun_id.as_bytes(),previous.attempt_id.as_bytes(),previous.cycle_id.as_bytes(),previous.proposal_index as i64,previous.semantic_digest.as_bytes(),previous.result_digest.as_bytes(),request.identity.fence.0 as i64,(request.round_index-1) as i64,expected_budget,expected_started],
                |r| r.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        if !valid {
            return Err(Error::IdempotencyConflict);
        }
    }
    Ok(())
}

pub(crate) fn verify_previous_tool_permission(
    connection: &rusqlite::Connection,
    runtime_authority: &str,
    taskrun_id: runne_domain::id::TaskRunId,
    current_round: u32,
    previous: runne_application::ports::TaskRunProviderToolResultRef,
    assignment: &runne_application::ports::TaskRunAssignmentIdentity,
    now: i64,
) -> Result<(), Error> {
    let expected_round = current_round.checked_sub(1).ok_or(Error::NotPrepared)?;
    type Previous = (
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        Option<i64>,
        i64,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        i64,
    );
    let row: Previous = connection
        .query_row(
            "SELECT semantic_digest,result_digest,state,result_truncated,release_started,
                    local_stop_state,managed_area_identity,empty_proof_identity,round_index
             FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2
               AND cycle_id=?3 AND proposal_index=?4",
            rusqlite::params![
                taskrun_id.as_bytes(),
                previous.attempt_id.as_bytes(),
                previous.cycle_id.as_bytes(),
                i64::from(previous.proposal_index)
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
                ))
            },
        )
        .map_err(|_| Error::IdempotencyConflict)?;
    if row.0.as_slice() != previous.semantic_digest.as_bytes()
        || row.1.as_deref() != Some(previous.result_digest.as_bytes().as_slice())
        || row.2 != "result"
        || row.3 != Some(0)
        || row.4 != 1
        || row.5 != 2
        || row.6.is_none()
        || row.6 != row.7
        || row.8 != i64::from(expected_round)
    {
        return Err(Error::IdempotencyConflict);
    }
    match crate::store::taskrun_tool_invocation::permission_is_current_on_connection(
        connection,
        runtime_authority,
        crate::store::taskrun_tool_invocation::ToolInvocationKey {
            taskrun_id,
            attempt_id: previous.attempt_id,
            cycle_id: previous.cycle_id,
            proposal_index: previous.proposal_index,
        },
        previous.semantic_digest,
        assignment,
        now,
    ) {
        Ok(true) => Ok(()),
        Err(crate::store::taskrun_tool_invocation::ToolInvocationStoreError::Unavailable) => {
            Err(Error::Unavailable)
        }
        Err(crate::store::taskrun_tool_invocation::ToolInvocationStoreError::CorruptData) => {
            Err(Error::CorruptData)
        }
        _ => Err(Error::IdempotencyConflict),
    }
}

pub(crate) fn compact_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
