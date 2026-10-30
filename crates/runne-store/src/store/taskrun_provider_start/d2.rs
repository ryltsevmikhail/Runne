use super::*;

type AdmittedRoundBindingRow = (
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

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
    let coding = selected.profile_id()
        == super::super::taskrun_tool_invocation::budget_policy::CODING_PROFILE;
    if (!coding && selected.profile_id() != "runne-linux-agent-tools-v1")
        || selected.profile_digest() != &profile_digest
    {
        return Err(());
    }

    let cycle = snapshot.active_cycle().ok_or(())?;
    let plan = cycle.plan_revision_ref.as_ref().ok_or(())?;
    let expected_indexes = if coding {
        (0..cycle.expected_proposal_indexes.len() as u32).collect::<Vec<_>>()
    } else {
        vec![0, 1]
    };
    if coding
        && !coding_prefix_settled(
            &cycle.expected_proposal_indexes,
            cycle.recorded_outcomes.len(),
            cycle
                .recorded_outcomes
                .iter()
                .all(|o| o.outcome_type == runne_domain::agent_loop::StepOutcomeType::Succeeded),
        )
    {
        return Err(());
    }
    if cycle.attempt_id != attempt_id
        || !matches!(
            cycle.state,
            runne_domain::agent_loop::LoopCycleState::Acting
                | runne_domain::agent_loop::LoopCycleState::Evaluating
        )
        || cycle.expected_proposal_indexes != expected_indexes
        || plan.taskrun_id != taskrun_id
        || plan.cycle_id != cycle.cycle_id
        || plan.expected_proposal_indexes != expected_indexes
        || plan.context_manifest_ref.taskrun_id != taskrun_id
        || plan.context_manifest_ref.attempt_id != attempt_id
        || plan.context_manifest_ref.cycle_id != cycle.cycle_id
    {
        return Err(());
    }
    let limits =
        super::super::taskrun_tool_invocation::budget_policy::limits(connection, taskrun_id)
            .map_err(|_| ())?;
    if limits.0 != if coding { 32 } else { 2 } {
        return Err(());
    }
    let budget: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets b JOIN taskrun_assignment_occupations o ON o.taskrun_id=b.taskrun_id AND o.attempt_id=b.attempt_id AND o.fence=b.fence WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND o.state='active' AND b.effects_used<=b.effects_limit AND b.continuations_used<=b.continuations_limit)",
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
    let (
        fence,
        node,
        node_epoch,
        round_head,
        round_index,
        previous_attempt,
        previous_cycle,
        previous_proposal,
        previous_semantic,
        previous_result,
    ): AdmittedRoundBindingRow = connection
        .query_row(
            "SELECT b.fence,b.node_id,b.node_epoch,b.current_taskrun_head,b.round_index,
                        b.previous_attempt_id,b.previous_cycle_id,b.previous_proposal_index,
                        b.previous_semantic_digest,b.previous_result_digest
                 FROM taskrun_provider_round_bindings b
                 JOIN provider_execution_admissions a ON a.call_id=b.call_id
                 WHERE a.dispatch_attempt_id=?1 AND b.taskrun_id=?2 AND b.attempt_id=?3
                   AND b.profile_digest=?4",
            rusqlite::params![
                dispatch_attempt_id.as_slice(),
                taskrun_id.as_bytes(),
                attempt_id.as_bytes(),
                profile_digest.as_slice()
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
                ))
            },
        )
        .map_err(|_| ())?;
    if !(0..=i64::from(
        super::super::taskrun_tool_invocation::budget_policy::limits(connection, taskrun_id)
            .map_err(|_| ())?
            .1,
    ))
        .contains(&round_index)
    {
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
    if round_index == 0 {
        if previous_attempt.is_some()
            || previous_cycle.is_some()
            || previous_proposal.is_some()
            || previous_semantic.is_some()
            || previous_result.is_some()
        {
            return Err(());
        }
    } else {
        let previous = runne_application::ports::TaskRunProviderToolResultRef {
            attempt_id: AttemptId::from_bytes(
                previous_attempt.ok_or(())?.try_into().map_err(|_| ())?,
            ),
            cycle_id: runne_domain::id::CycleId::from_bytes(
                previous_cycle.ok_or(())?.try_into().map_err(|_| ())?,
            ),
            proposal_index: u32::try_from(previous_proposal.ok_or(())?).map_err(|_| ())?,
            semantic_digest: runne_domain::id::IntegrityDigest::from_bytes(
                previous_semantic.ok_or(())?.try_into().map_err(|_| ())?,
            ),
            result_digest: runne_domain::id::IntegrityDigest::from_bytes(
                previous_result.ok_or(())?.try_into().map_err(|_| ())?,
            ),
        };
        let node: [u8; 16] = node.try_into().map_err(|_| ())?;
        let assignment = runne_application::ports::TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id,
            node_id: runne_application::ports::ExecutionNodeId(
                uuid::Uuid::from_bytes(node).to_string(),
            ),
            node_epoch: u64::try_from(node_epoch).map_err(|_| ())?,
            fence: runne_application::ports::TaskRunFence(u64::try_from(fence).map_err(|_| ())?),
        };
        super::super::taskrun_provider_round_binding::verify_previous_tool_permission(
            connection,
            &super::super::taskrun_provider_round_binding::compact_hex(&authority),
            taskrun_id,
            u32::try_from(round_index).map_err(|_| ())?,
            previous,
            &assignment,
            now,
        )
        .map_err(|_| ())?;
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

fn coding_prefix_settled(indexes: &[u32], outcomes: usize, all_succeeded: bool) -> bool {
    indexes.len() <= 32
        && outcomes == indexes.len()
        && all_succeeded
        && indexes.iter().enumerate().all(|(i, n)| *n as usize == i)
}
#[cfg(test)]
mod coding_plan_tests {
    use super::coding_prefix_settled;
    #[test]
    fn coding_provider_admits_zero_and_completed_extended_prefix_only() {
        assert!(coding_prefix_settled(&[], 0, true));
        assert!(coding_prefix_settled(&[0, 1], 2, true));
        assert!(coding_prefix_settled(
            &(0..32).collect::<Vec<_>>(),
            32,
            true
        ));
        assert!(!coding_prefix_settled(&[0, 1], 1, true));
        assert!(!coding_prefix_settled(&[0, 1], 2, false));
        assert!(!coding_prefix_settled(&[0, 2], 2, true));
        assert!(!coding_prefix_settled(
            &(0..33).collect::<Vec<_>>(),
            33,
            true
        ));
    }
}
