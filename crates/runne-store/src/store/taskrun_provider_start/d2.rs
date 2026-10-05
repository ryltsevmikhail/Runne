use super::*;

pub(super) fn verify_plan_and_budget(
    connection: &Connection,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    profile_digest: [u8; 32],
) -> Result<(), ()> {
    let verified = taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
        .map_err(|_| ())?;
    let task = runne_domain::task_run::TaskRun::replay(&verified.events).map_err(|_| ())?;
    let snapshot = task.snapshot_v1();
    let selected = snapshot
        .input()
        .and_then(runne_domain::task_run::TaskRunInput::selected_profile)
        .ok_or(())?;
    if selected.profile_id() != "runne-linux-agent-tools-v1"
        || selected.profile_digest() != &profile_digest
    {
        return Err(());
    }
    let cycle = snapshot.active_cycle().ok_or(())?;
    let plan = cycle.plan_revision_ref.as_ref().ok_or(())?;
    if cycle.attempt_id != attempt_id
        || !matches!(
            cycle.state,
            runne_domain::agent_loop::LoopCycleState::Acting
                | runne_domain::agent_loop::LoopCycleState::Evaluating
        )
        || cycle.expected_proposal_indexes != [0, 1]
        || plan.taskrun_id != taskrun_id
        || plan.cycle_id != cycle.cycle_id
        || plan.expected_proposal_indexes != [0, 1]
        || plan.context_manifest_ref.taskrun_id != taskrun_id
        || plan.context_manifest_ref.attempt_id != attempt_id
        || plan.context_manifest_ref.cycle_id != cycle.cycle_id
    {
        return Err(());
    }
    let budget: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets b JOIN taskrun_assignment_occupations o ON o.taskrun_id=b.taskrun_id AND o.attempt_id=b.attempt_id AND o.fence=b.fence WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND o.state='active' AND b.effects_limit=2 AND b.continuations_limit=2 AND b.effects_used<=2 AND b.continuations_used<=2)",
            rusqlite::params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    if budget { Ok(()) } else { Err(()) }
}

// The complete immutable provider round is compared within this read snapshot.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_admitted_round(
    connection: &Connection,
    dispatch_attempt_id: &[u8; 16],
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    authority: [u8; 16],
    conversation_id: ConversationId,
    principal: &str,
    profile_digest: [u8; 32],
) -> Result<(), ()> {
    let (fence, node, node_epoch, round_head, round_index): (i64, Vec<u8>, i64, i64, i64) =
        connection
            .query_row(
                "SELECT b.fence,b.node_id,b.node_epoch,b.current_taskrun_head,b.round_index FROM taskrun_provider_round_bindings b JOIN provider_execution_admissions a ON a.call_id=b.call_id WHERE a.dispatch_attempt_id=?1 AND b.taskrun_id=?2 AND b.attempt_id=?3 AND b.profile_digest=?4",
                rusqlite::params![dispatch_attempt_id.as_slice(),taskrun_id.as_bytes(),attempt_id.as_bytes(),profile_digest.as_slice()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )
            .map_err(|_| ())?;
    if !(0..=2).contains(&round_index) {
        return Err(());
    }
    let current_head: i64 = connection
        .query_row(
            "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    let now: i64 = connection
        .query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    let active: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='active' AND lease_expires_at_ms>?6)",
            rusqlite::params![taskrun_id.as_bytes(),fence,attempt_id.as_bytes(),node,node_epoch,now],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    if round_head != current_head || !active {
        return Err(());
    }
    super::verify_fresh_d2_running_attempt(
        connection,
        authority,
        taskrun_id,
        conversation_id,
        attempt_id,
        principal,
        profile_digest,
    )
}
