use runne_domain::{
    agent_loop::{ActiveLoopCycle, LoopCycleState},
    id::AttemptId,
};

pub(super) fn valid_retained_early_cycle(
    cycle: Option<&ActiveLoopCycle>,
    claim_version: i64,
    terminal_version: u64,
    attempt_id: AttemptId,
) -> bool {
    let terminal_version = match i64::try_from(terminal_version) {
        Ok(version) => version,
        Err(_) => return false,
    };
    let expected_terminal_version = match cycle {
        None => claim_version.checked_add(1),
        Some(cycle)
            if cycle.attempt_id == attempt_id
                && cycle.plan_revision_ref.is_none()
                && cycle.expected_proposal_indexes.is_empty()
                && cycle.recorded_outcomes.is_empty()
                && cycle.state == LoopCycleState::Observing
                && cycle.context_manifest_ref.is_none() =>
        {
            claim_version.checked_add(2)
        }
        Some(cycle)
            if cycle.attempt_id == attempt_id
                && cycle.plan_revision_ref.is_none()
                && cycle.expected_proposal_indexes.is_empty()
                && cycle.recorded_outcomes.is_empty()
                && cycle.state == LoopCycleState::Proposing
                && cycle.context_manifest_ref.is_some() =>
        {
            claim_version.checked_add(3)
        }
        Some(_) => None,
    };
    expected_terminal_version == Some(terminal_version)
}
