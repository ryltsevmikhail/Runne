use super::{TaskRun, TaskRunSnapshotError, io};
use crate::task_run::TaskRunState;
use std::collections::BTreeSet;

pub(super) fn validate(value: &TaskRun) -> Result<(), TaskRunSnapshotError> {
    if value.attempt_history.len() > io::MAX_ITEMS
        || value.cycle_history.len() > io::MAX_ITEMS
        || !unique_attempts(&value.attempt_history)
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if !lifecycle_is_valid(value) {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if value.state == TaskRunState::Succeeded && value.terminal_result.is_none()
        || value.state != TaskRunState::Succeeded && value.terminal_result.is_some()
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if value.pending_retry.is_some() && value.state != TaskRunState::Retrying {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if value.pending_loop_checkpoint.is_some()
        || value.recovery_generation > value.attempt_history.len().saturating_sub(1) as u64
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if value.attempt_history.is_empty()
        && (value.active_attempt.is_some()
            || value.active_cycle.is_some()
            || value.last_completed_cycle.is_some()
            || value.pending_successor.is_some()
            || value.pending_loop_wait.is_some()
            || value.pending_retry.is_some()
            || value.pending_loop_checkpoint.is_some()
            || !value.cycle_history.is_empty())
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if !history_is_canonical(&value.attempt_history, &value.cycle_history) {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    if value
        .active_cycle
        .as_ref()
        .is_some_and(|cycle| !active_cycle_is_valid(value, cycle))
        || value
            .last_completed_cycle
            .as_ref()
            .is_some_and(|cycle| !completed_cycle_is_valid(value, cycle))
        || value
            .pending_successor
            .as_ref()
            .is_some_and(|pending| !successor_is_valid(value, pending))
        || value
            .pending_loop_wait
            .as_ref()
            .is_some_and(|pending| !wait_is_valid(value, pending))
        || value
            .pending_retry
            .as_ref()
            .is_some_and(|pending| !retry_is_valid(value, pending))
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    Ok(())
}

fn unique_attempts(values: &[crate::id::AttemptId]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}
fn lifecycle_is_valid(value: &TaskRun) -> bool {
    let has_attempts = !value.attempt_history.is_empty();
    let active_is_latest = value.active_attempt == value.attempt_history.last().copied();
    match value.state {
        TaskRunState::Created | TaskRunState::Queued | TaskRunState::Admitted => {
            !has_attempts && value.active_attempt.is_none()
        }
        TaskRunState::Running
        | TaskRunState::Waiting
        | TaskRunState::Retrying
        | TaskRunState::Checkpointing
        | TaskRunState::Reconciling => has_attempts && active_is_latest,
        TaskRunState::Cancelling => {
            (!has_attempts && value.active_attempt.is_none()) || (has_attempts && active_is_latest)
        }
        TaskRunState::Cancelled => value.active_attempt.is_none(),
        TaskRunState::Succeeded
        | TaskRunState::Failed
        | TaskRunState::BudgetExhausted
        | TaskRunState::PolicyDenied
        | TaskRunState::Unrecoverable => has_attempts && value.active_attempt.is_none(),
    }
}
fn history_is_canonical(
    attempts: &[crate::id::AttemptId],
    history: &[crate::agent_loop::CycleHistoryEntry],
) -> bool {
    let mut seen_cycles = BTreeSet::new();
    let mut previous_attempt_index = None;
    let mut previous_entry: Option<&crate::agent_loop::CycleHistoryEntry> = None;
    for entry in history {
        let Some(attempt_index) = attempts.iter().position(|id| *id == entry.attempt_id) else {
            return false;
        };
        if !seen_cycles.insert(entry.cycle_id) {
            return false;
        }
        let is_new_epoch = previous_attempt_index != Some(attempt_index);
        if is_new_epoch {
            if previous_attempt_index.is_some_and(|previous| attempt_index <= previous)
                || entry.sequence != 0
                || entry.parent_cycle_id.is_some()
            {
                return false;
            }
        } else if let Some(previous) = previous_entry
            && (previous.sequence.checked_add(1) != Some(entry.sequence)
                || entry.parent_cycle_id != Some(previous.cycle_id))
        {
            return false;
        }
        previous_attempt_index = Some(attempt_index);
        previous_entry = Some(entry);
    }
    true
}
fn active_cycle_is_valid(value: &TaskRun, cycle: &crate::agent_loop::ActiveLoopCycle) -> bool {
    if !value.attempt_history.contains(&cycle.attempt_id)
        || !value.cycle_history.iter().any(|entry| {
            entry.cycle_id == cycle.cycle_id
                && entry.attempt_id == cycle.attempt_id
                && entry.sequence == cycle.sequence
                && entry.parent_cycle_id == cycle.parent_cycle_id
        })
    {
        return false;
    }
    if !canonical_indexes(&cycle.expected_proposal_indexes)
        || cycle.recorded_outcomes.iter().any(|outcome| {
            !cycle
                .expected_proposal_indexes
                .contains(&outcome.proposal_index)
                || !TaskRun::outcome_cardinality_is_valid(outcome)
        })
        || !unique_outcomes(&cycle.recorded_outcomes)
    {
        return false;
    }
    let context_matches = cycle.context_manifest_ref.as_ref().is_some_and(|context| {
        context.taskrun_id == value.id
            && context.attempt_id == cycle.attempt_id
            && context.cycle_id == cycle.cycle_id
    });
    let plan_matches = match (
        cycle.plan_revision_ref.as_ref(),
        cycle.context_manifest_ref.as_ref(),
    ) {
        (Some(plan), Some(context)) => {
            context_matches
                && plan.taskrun_id == value.id
                && plan.cycle_id == cycle.cycle_id
                && plan.context_manifest_ref == *context
                && plan.expected_proposal_indexes == cycle.expected_proposal_indexes
        }
        _ => false,
    };
    match cycle.state {
        crate::agent_loop::LoopCycleState::Observing => {
            cycle.context_manifest_ref.is_none()
                && cycle.plan_revision_ref.is_none()
                && cycle.expected_proposal_indexes.is_empty()
                && cycle.recorded_outcomes.is_empty()
        }
        crate::agent_loop::LoopCycleState::Proposing => {
            context_matches
                && cycle.plan_revision_ref.is_none()
                && cycle.expected_proposal_indexes.is_empty()
                && cycle.recorded_outcomes.is_empty()
        }
        crate::agent_loop::LoopCycleState::Acting => {
            plan_matches && !cycle.expected_proposal_indexes.is_empty()
        }
        crate::agent_loop::LoopCycleState::Evaluating => {
            plan_matches
                && cycle.expected_proposal_indexes.iter().all(|index| {
                    cycle
                        .recorded_outcomes
                        .iter()
                        .any(|outcome| outcome.proposal_index == *index)
                })
        }
        crate::agent_loop::LoopCycleState::Completed => false,
    }
}
fn canonical_indexes(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
fn unique_outcomes(values: &[crate::agent_loop::StepOutcomeRecord]) -> bool {
    let mut indexes = BTreeSet::new();
    let mut steps = BTreeSet::new();
    values
        .iter()
        .all(|outcome| indexes.insert(outcome.proposal_index) && steps.insert(outcome.step_id))
}
fn completed_cycle_is_valid(value: &TaskRun, cycle: &crate::agent_loop::CompletedCycleRef) -> bool {
    let history = value.cycle_history.iter().any(|entry| {
        entry.cycle_id == cycle.cycle_id
            && entry.attempt_id == cycle.attempt_id
            && entry.sequence == cycle.sequence
    });
    let evidence = match (&cycle.disposition, &cycle.accepted_wake_evidence) {
        (crate::agent_loop::LoopDisposition::Wait { wake_condition, .. }, Some(evidence)) => {
            evidence.cycle_id == cycle.cycle_id
                && evidence.condition_digest == wake_condition.condition_digest
        }
        (crate::agent_loop::LoopDisposition::Wait { .. }, None) | (_, None) => true,
        _ => false,
    };
    history
        && evidence
        && !matches!(
            &cycle.disposition,
            crate::agent_loop::LoopDisposition::Complete { plan_evaluation_ref }
                if plan_evaluation_ref.taskrun_id != value.id
                    || plan_evaluation_ref.result != crate::verification::PlanEvaluationResult::Passed
        )
}
fn successor_is_valid(value: &TaskRun, pending: &crate::agent_loop::PendingSuccessorCycle) -> bool {
    value.active_cycle.is_none()
        && value.last_completed_cycle.as_ref().is_some_and(|cycle| {
            cycle.cycle_id == pending.parent_cycle_id
                && cycle.attempt_id == pending.attempt_id
                && cycle.successor_allocated
                && cycle.sequence.checked_add(1) == Some(pending.sequence)
                && matches!(
                    cycle.disposition,
                    crate::agent_loop::LoopDisposition::Continue
                        | crate::agent_loop::LoopDisposition::Wait { .. }
                )
        })
        && !value
            .cycle_history
            .iter()
            .any(|entry| entry.cycle_id == pending.successor_cycle_id)
}
fn wait_is_valid(value: &TaskRun, pending: &crate::agent_loop::PendingLoopWait) -> bool {
    value.last_completed_cycle.as_ref().is_some_and(|cycle| matches!(&cycle.disposition, crate::agent_loop::LoopDisposition::Wait { wake_condition, .. } if cycle.cycle_id == pending.cycle_id && *wake_condition == pending.wake_condition))
}
fn retry_is_valid(value: &TaskRun, pending: &crate::agent_loop::PendingRetry) -> bool {
    value.active_attempt == Some(pending.old_attempt_id)
        && value.cycle_history.iter().any(|cycle| {
            cycle.cycle_id == pending.abandoned_cycle_id
                && cycle.attempt_id == pending.old_attempt_id
        })
        && pending.step_outcome_ref.cycle_id == pending.abandoned_cycle_id
        && !value.attempt_history.contains(&pending.new_attempt_id)
        && pending.budget_reservation_ref.taskrun_id == value.id
        && pending.budget_reservation_ref.attempt_id == pending.old_attempt_id
        && pending.budget_reservation_ref.retry_ordinal == pending.ordinal
}
