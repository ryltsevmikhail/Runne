use super::TaskRunSnapshotError;
use super::io::{In, Out};
use super::refs::{
    canonical, get_budget, get_eval, get_evidence, get_outcome, get_step_ref, get_wake, put_budget,
    put_eval, put_evidence, put_outcome, put_step_ref, put_wake,
};
use crate::agent_loop::{
    ActiveLoopCycle, CompletedCycleRef, CycleHistoryEntry, LoopCycleState, LoopDisposition,
    PendingLoopCheckpoint, PendingLoopWait, PendingRetry, PendingSuccessorCycle,
};
use crate::id::{AttemptId, CheckpointId, CycleId};

#[path = "cycles/options.rs"]
mod options;
use options::{
    bool, get_indexes, get_opt_context, get_opt_cycle, get_opt_plan, put_opt_context,
    put_opt_cycle, put_opt_plan, unique_outcomes,
};

pub(super) fn put_active(
    out: &mut Out,
    value: &ActiveLoopCycle,
) -> Result<(), TaskRunSnapshotError> {
    out.id(value.cycle_id.as_bytes());
    out.id(value.attempt_id.as_bytes());
    out.u64(value.sequence);
    put_opt_cycle(out, value.parent_cycle_id);
    out.u8(match value.state {
        LoopCycleState::Observing => 1,
        LoopCycleState::Proposing => 2,
        LoopCycleState::Acting => 3,
        LoopCycleState::Evaluating => 4,
        LoopCycleState::Completed => 5,
    });
    put_opt_context(out, value.context_manifest_ref.as_ref())?;
    put_opt_plan(out, value.plan_revision_ref.as_ref())?;
    out.len(value.expected_proposal_indexes.len())?;
    for index in &value.expected_proposal_indexes {
        out.u32(*index);
    }
    out.len(value.recorded_outcomes.len())?;
    for outcome in &value.recorded_outcomes {
        put_outcome(out, outcome)?;
    }
    Ok(())
}
pub(super) fn get_active(input: &mut In<'_>) -> Result<ActiveLoopCycle, TaskRunSnapshotError> {
    let cycle_id = CycleId::from_bytes(input.id()?);
    let attempt_id = AttemptId::from_bytes(input.id()?);
    let sequence = input.u64()?;
    let parent_cycle_id = get_opt_cycle(input)?;
    let state = match input.u8()? {
        1 => LoopCycleState::Observing,
        2 => LoopCycleState::Proposing,
        3 => LoopCycleState::Acting,
        4 => LoopCycleState::Evaluating,
        5 => LoopCycleState::Completed,
        _ => return Err(TaskRunSnapshotError::InvalidEncoding),
    };
    let context_manifest_ref = get_opt_context(input)?;
    let plan_revision_ref = get_opt_plan(input)?;
    let expected_proposal_indexes = get_indexes(input)?;
    let count = input.len()?;
    let mut recorded_outcomes = Vec::with_capacity(count);
    for _ in 0..count {
        recorded_outcomes.push(get_outcome(input)?);
    }
    if !canonical(&expected_proposal_indexes)
        || recorded_outcomes
            .iter()
            .any(|outcome| !expected_proposal_indexes.contains(&outcome.proposal_index))
        || !unique_outcomes(&recorded_outcomes)
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    Ok(ActiveLoopCycle {
        cycle_id,
        attempt_id,
        sequence,
        parent_cycle_id,
        state,
        context_manifest_ref,
        plan_revision_ref,
        expected_proposal_indexes,
        recorded_outcomes,
    })
}

pub(super) fn put_completed(
    out: &mut Out,
    value: &CompletedCycleRef,
) -> Result<(), TaskRunSnapshotError> {
    out.id(value.cycle_id.as_bytes());
    out.id(value.attempt_id.as_bytes());
    out.u64(value.sequence);
    put_disposition(out, &value.disposition)?;
    match &value.accepted_wake_evidence {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            put_evidence(out, value)?;
        }
    }
    out.u8(u8::from(value.successor_allocated));
    Ok(())
}
pub(super) fn get_completed(input: &mut In<'_>) -> Result<CompletedCycleRef, TaskRunSnapshotError> {
    let cycle_id = CycleId::from_bytes(input.id()?);
    let attempt_id = AttemptId::from_bytes(input.id()?);
    let sequence = input.u64()?;
    let disposition = get_disposition(input)?;
    let accepted_wake_evidence = match input.u8()? {
        0 => None,
        1 => Some(get_evidence(input)?),
        _ => return Err(TaskRunSnapshotError::InvalidEncoding),
    };
    let successor_allocated = bool(input)?;
    if accepted_wake_evidence
        .as_ref()
        .is_some_and(|value| value.cycle_id != cycle_id)
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    Ok(CompletedCycleRef {
        cycle_id,
        attempt_id,
        sequence,
        disposition,
        accepted_wake_evidence,
        successor_allocated,
    })
}

fn put_disposition(out: &mut Out, value: &LoopDisposition) -> Result<(), TaskRunSnapshotError> {
    match value {
        LoopDisposition::Continue => out.u8(1),
        LoopDisposition::Wait {
            reason,
            wake_condition,
        } => {
            out.u8(2);
            out.string(reason)?;
            put_wake(out, wake_condition)?;
        }
        LoopDisposition::Complete {
            plan_evaluation_ref,
        } => {
            out.u8(3);
            put_eval(out, plan_evaluation_ref);
        }
        LoopDisposition::Fail {
            reason,
            unresolved_proposals,
        } => {
            out.u8(4);
            out.string(reason)?;
            out.len(unresolved_proposals.len())?;
            for index in unresolved_proposals {
                out.u32(*index);
            }
        }
    }
    Ok(())
}
fn get_disposition(input: &mut In<'_>) -> Result<LoopDisposition, TaskRunSnapshotError> {
    match input.u8()? {
        1 => Ok(LoopDisposition::Continue),
        2 => Ok(LoopDisposition::Wait {
            reason: input.string()?,
            wake_condition: get_wake(input)?,
        }),
        3 => Ok(LoopDisposition::Complete {
            plan_evaluation_ref: get_eval(input)?,
        }),
        4 => Ok(LoopDisposition::Fail {
            reason: input.string()?,
            unresolved_proposals: get_indexes(input)?,
        }),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}

pub(super) fn put_history(out: &mut Out, value: &CycleHistoryEntry) {
    out.id(value.cycle_id.as_bytes());
    out.id(value.attempt_id.as_bytes());
    out.u64(value.sequence);
    put_opt_cycle(out, value.parent_cycle_id);
}
pub(super) fn get_history(input: &mut In<'_>) -> Result<CycleHistoryEntry, TaskRunSnapshotError> {
    Ok(CycleHistoryEntry {
        cycle_id: CycleId::from_bytes(input.id()?),
        attempt_id: AttemptId::from_bytes(input.id()?),
        sequence: input.u64()?,
        parent_cycle_id: get_opt_cycle(input)?,
    })
}
pub(super) fn put_successor(out: &mut Out, value: &PendingSuccessorCycle) {
    out.id(value.parent_cycle_id.as_bytes());
    out.id(value.successor_cycle_id.as_bytes());
    out.id(value.attempt_id.as_bytes());
    out.u64(value.sequence);
}
pub(super) fn get_successor(
    input: &mut In<'_>,
) -> Result<PendingSuccessorCycle, TaskRunSnapshotError> {
    Ok(PendingSuccessorCycle {
        parent_cycle_id: CycleId::from_bytes(input.id()?),
        successor_cycle_id: CycleId::from_bytes(input.id()?),
        attempt_id: AttemptId::from_bytes(input.id()?),
        sequence: input.u64()?,
    })
}
pub(super) fn put_wait(out: &mut Out, value: &PendingLoopWait) -> Result<(), TaskRunSnapshotError> {
    out.id(value.cycle_id.as_bytes());
    put_wake(out, &value.wake_condition)
}
pub(super) fn get_wait(input: &mut In<'_>) -> Result<PendingLoopWait, TaskRunSnapshotError> {
    Ok(PendingLoopWait {
        cycle_id: CycleId::from_bytes(input.id()?),
        wake_condition: get_wake(input)?,
    })
}
pub(super) fn put_retry(out: &mut Out, value: &PendingRetry) {
    out.u64(value.ordinal);
    out.id(value.old_attempt_id.as_bytes());
    out.id(value.new_attempt_id.as_bytes());
    out.id(value.abandoned_cycle_id.as_bytes());
    put_step_ref(out, &value.step_outcome_ref);
    out.i64(value.due_at_unix_us);
    out.u64(value.delay_ms);
    put_budget(out, &value.budget_reservation_ref);
    out.digest(value.retry_policy_digest);
}
pub(super) fn get_retry(input: &mut In<'_>) -> Result<PendingRetry, TaskRunSnapshotError> {
    Ok(PendingRetry {
        ordinal: input.u64()?,
        old_attempt_id: AttemptId::from_bytes(input.id()?),
        new_attempt_id: AttemptId::from_bytes(input.id()?),
        abandoned_cycle_id: CycleId::from_bytes(input.id()?),
        step_outcome_ref: get_step_ref(input)?,
        due_at_unix_us: input.i64()?,
        delay_ms: input.u64()?,
        budget_reservation_ref: get_budget(input)?,
        retry_policy_digest: input.digest()?,
    })
}
pub(super) fn put_checkpoint(out: &mut Out, value: &PendingLoopCheckpoint) {
    out.id(value.checkpoint_id.as_bytes());
    out.u64(value.start_position);
    out.digest(value.expected_integrity_digest);
    match value.recorded_integrity_digest {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.digest(value);
        }
    }
}
pub(super) fn get_checkpoint(
    input: &mut In<'_>,
) -> Result<PendingLoopCheckpoint, TaskRunSnapshotError> {
    Ok(PendingLoopCheckpoint {
        checkpoint_id: CheckpointId::from_bytes(input.id()?),
        start_position: input.u64()?,
        expected_integrity_digest: input.digest()?,
        recorded_integrity_digest: match input.u8()? {
            0 => None,
            1 => Some(input.digest()?),
            _ => return Err(TaskRunSnapshotError::InvalidEncoding),
        },
    })
}
