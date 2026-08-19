use super::TaskRunSnapshotError;
use super::io::{In, Out};
use crate::agent_loop::{StepOutcomeRecord, StepOutcomeRef, StepOutcomeType};
use crate::context::ContextManifestRef;
use crate::id::{
    AttemptId, BudgetReservationId, ContextManifestId, CycleId, EffectId, PlanId, ResultId, StepId,
    TaskRunId,
};
use crate::plan::{PlanParentRef, PlanRevisionRef};
use crate::reference::{BudgetReservationRef, ResultRef};

#[path = "refs/tail.rs"]
mod tail;
pub(in crate::task_run::snapshot) use tail::{
    get_eval, get_evidence, get_wake, put_eval, put_evidence, put_wake,
};

pub(super) fn put_context(
    out: &mut Out,
    value: &ContextManifestRef,
) -> Result<(), TaskRunSnapshotError> {
    out.id(value.manifest_id.as_bytes());
    out.id(value.taskrun_id.as_bytes());
    out.id(value.attempt_id.as_bytes());
    out.id(value.cycle_id.as_bytes());
    out.u64(value.revision);
    out.string(&value.policy_revision)?;
    out.digest(value.integrity_digest);
    Ok(())
}
pub(super) fn get_context(input: &mut In<'_>) -> Result<ContextManifestRef, TaskRunSnapshotError> {
    Ok(ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes(input.id()?),
        taskrun_id: TaskRunId::from_bytes(input.id()?),
        attempt_id: AttemptId::from_bytes(input.id()?),
        cycle_id: CycleId::from_bytes(input.id()?),
        revision: input.u64()?,
        policy_revision: input.string()?,
        integrity_digest: input.digest()?,
    })
}

fn put_result(out: &mut Out, value: &ResultRef) -> Result<(), TaskRunSnapshotError> {
    out.id(value.result_id().as_bytes());
    out.string(value.media_type())?;
    out.digest(*value.integrity_digest());
    Ok(())
}
fn get_result(input: &mut In<'_>) -> Result<ResultRef, TaskRunSnapshotError> {
    ResultRef::new(
        ResultId::from_bytes(input.id()?),
        input.string()?,
        input.digest()?,
    )
    .map_err(|_| TaskRunSnapshotError::InvalidEncoding)
}
pub(super) fn put_budget(out: &mut Out, value: &BudgetReservationRef) {
    out.id(value.reservation_id.as_bytes());
    out.id(value.taskrun_id.as_bytes());
    out.id(value.attempt_id.as_bytes());
    out.u64(value.retry_ordinal);
    out.digest(value.reservation_digest);
}
pub(super) fn get_budget(input: &mut In<'_>) -> Result<BudgetReservationRef, TaskRunSnapshotError> {
    Ok(BudgetReservationRef {
        reservation_id: BudgetReservationId::from_bytes(input.id()?),
        taskrun_id: TaskRunId::from_bytes(input.id()?),
        attempt_id: AttemptId::from_bytes(input.id()?),
        retry_ordinal: input.u64()?,
        reservation_digest: input.digest()?,
    })
}

pub(super) fn put_plan(out: &mut Out, value: &PlanRevisionRef) -> Result<(), TaskRunSnapshotError> {
    out.id(value.plan_id.as_bytes());
    out.id(value.taskrun_id.as_bytes());
    out.id(value.cycle_id.as_bytes());
    out.u64(value.revision);
    put_context(out, &value.context_manifest_ref)?;
    out.len(value.expected_proposal_indexes.len())?;
    for index in &value.expected_proposal_indexes {
        out.u32(*index);
    }
    out.digest(value.proposal_batch_digest);
    put_result(out, &value.planning_policy_ref)?;
    put_budget(out, &value.planning_budget_ref);
    match &value.parent_ref {
        None => out.u8(0),
        Some(parent) => {
            out.u8(1);
            out.id(parent.plan_id.as_bytes());
            out.u64(parent.revision);
            out.digest(parent.integrity_digest);
        }
    }
    out.digest(value.integrity_digest);
    Ok(())
}
pub(super) fn get_plan(input: &mut In<'_>) -> Result<PlanRevisionRef, TaskRunSnapshotError> {
    let plan_id = PlanId::from_bytes(input.id()?);
    let taskrun_id = TaskRunId::from_bytes(input.id()?);
    let cycle_id = CycleId::from_bytes(input.id()?);
    let revision = input.u64()?;
    let context_manifest_ref = get_context(input)?;
    let expected_proposal_indexes = get_indexes(input)?;
    let proposal_batch_digest = input.digest()?;
    let planning_policy_ref = get_result(input)?;
    let planning_budget_ref = get_budget(input)?;
    let parent_ref = match input.u8()? {
        0 => None,
        1 => Some(PlanParentRef {
            plan_id: PlanId::from_bytes(input.id()?),
            revision: input.u64()?,
            integrity_digest: input.digest()?,
        }),
        _ => return Err(TaskRunSnapshotError::InvalidEncoding),
    };
    let integrity_digest = input.digest()?;
    if context_manifest_ref.taskrun_id != taskrun_id
        || context_manifest_ref.cycle_id != cycle_id
        || !canonical(&expected_proposal_indexes)
    {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    Ok(PlanRevisionRef {
        plan_id,
        taskrun_id,
        cycle_id,
        revision,
        context_manifest_ref,
        expected_proposal_indexes,
        proposal_batch_digest,
        planning_policy_ref,
        planning_budget_ref,
        parent_ref,
        integrity_digest,
    })
}

pub(super) fn put_outcome(
    out: &mut Out,
    value: &StepOutcomeRecord,
) -> Result<(), TaskRunSnapshotError> {
    out.u32(value.proposal_index);
    out.id(value.step_id.as_bytes());
    out.u8(match value.outcome_type {
        StepOutcomeType::Succeeded => 1,
        StepOutcomeType::FailedBeforeCommit => 2,
        StepOutcomeType::FailedAfterCommit => 3,
        StepOutcomeType::Uncertain => 4,
        StepOutcomeType::Cancelled => 5,
    });
    put_opt_result(out, value.result_ref.as_ref())?;
    put_opt_id(out, value.effect_id.map(|v| v.into_bytes()));
    out.len(value.evidence_digests.len())?;
    for digest in &value.evidence_digests {
        out.digest(*digest);
    }
    Ok(())
}
pub(super) fn get_outcome(input: &mut In<'_>) -> Result<StepOutcomeRecord, TaskRunSnapshotError> {
    let proposal_index = input.u32()?;
    let step_id = StepId::from_bytes(input.id()?);
    let outcome_type = match input.u8()? {
        1 => StepOutcomeType::Succeeded,
        2 => StepOutcomeType::FailedBeforeCommit,
        3 => StepOutcomeType::FailedAfterCommit,
        4 => StepOutcomeType::Uncertain,
        5 => StepOutcomeType::Cancelled,
        _ => return Err(TaskRunSnapshotError::InvalidEncoding),
    };
    let result_ref = get_opt_result(input)?;
    let effect_id = get_opt_id(input)?.map(EffectId::from_bytes);
    let count = input.len()?;
    let mut evidence_digests = Vec::with_capacity(count);
    for _ in 0..count {
        evidence_digests.push(input.digest()?);
    }
    let result = StepOutcomeRecord {
        proposal_index,
        step_id,
        outcome_type,
        result_ref,
        effect_id,
        evidence_digests,
    };
    if !super::TaskRun::outcome_cardinality_is_valid(&result) {
        return Err(TaskRunSnapshotError::InvalidState);
    }
    Ok(result)
}

fn put_opt_result(out: &mut Out, value: Option<&ResultRef>) -> Result<(), TaskRunSnapshotError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            put_result(out, value)?;
        }
    }
    Ok(())
}
fn get_opt_result(input: &mut In<'_>) -> Result<Option<ResultRef>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(get_result(input)?)),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
fn put_opt_id(out: &mut Out, value: Option<[u8; 16]>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.id(&value);
        }
    }
}
fn get_opt_id(input: &mut In<'_>) -> Result<Option<[u8; 16]>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.id()?)),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}

pub(super) fn put_step_ref(out: &mut Out, value: &StepOutcomeRef) {
    out.id(value.cycle_id.as_bytes());
    out.u32(value.proposal_index);
    out.id(value.step_id.as_bytes());
    out.digest(value.outcome_digest);
}
pub(super) fn get_step_ref(input: &mut In<'_>) -> Result<StepOutcomeRef, TaskRunSnapshotError> {
    Ok(StepOutcomeRef {
        cycle_id: CycleId::from_bytes(input.id()?),
        proposal_index: input.u32()?,
        step_id: StepId::from_bytes(input.id()?),
        outcome_digest: input.digest()?,
    })
}

pub(super) fn canonical(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
fn get_indexes(input: &mut In<'_>) -> Result<Vec<u32>, TaskRunSnapshotError> {
    let count = input.len()?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(input.u32()?);
    }
    Ok(values)
}
