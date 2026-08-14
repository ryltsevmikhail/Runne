use super::super::TaskRunSnapshotError;
use super::super::io::{In, Out};
use crate::agent_loop::{WakeCondition, WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource};
use crate::id::{CycleId, PlanEvaluationId, PlanId, TaskRunId, WakeEvidenceId};
use crate::verification::{PlanEvaluationRef, PlanEvaluationResult};

pub(in crate::task_run::snapshot) fn put_wake(
    out: &mut Out,
    value: &WakeCondition,
) -> Result<(), TaskRunSnapshotError> {
    out.u8(match value.kind {
        WakeConditionKind::ExternalInput => 1,
        WakeConditionKind::Approval => 2,
        WakeConditionKind::ChildTaskRun => 3,
        WakeConditionKind::Timer => 4,
        WakeConditionKind::Reconciliation => 5,
    });
    out.string(&value.condition_ref)?;
    out.digest(value.condition_digest);
    Ok(())
}
pub(in crate::task_run::snapshot) fn get_wake(
    input: &mut In<'_>,
) -> Result<WakeCondition, TaskRunSnapshotError> {
    Ok(WakeCondition {
        kind: match input.u8()? {
            1 => WakeConditionKind::ExternalInput,
            2 => WakeConditionKind::Approval,
            3 => WakeConditionKind::ChildTaskRun,
            4 => WakeConditionKind::Timer,
            5 => WakeConditionKind::Reconciliation,
            _ => return Err(TaskRunSnapshotError::InvalidEncoding),
        },
        condition_ref: input.string()?,
        condition_digest: input.digest()?,
    })
}
pub(in crate::task_run::snapshot) fn put_evidence(
    out: &mut Out,
    value: &WakeEvidenceRef,
) -> Result<(), TaskRunSnapshotError> {
    out.id(value.cycle_id.as_bytes());
    out.digest(value.condition_digest);
    out.u8(match value.source {
        WakeEvidenceSource::ExternalInput => 1,
        WakeEvidenceSource::Approval => 2,
        WakeEvidenceSource::ChildTaskRun => 3,
        WakeEvidenceSource::Timer => 4,
        WakeEvidenceSource::Reconciliation => 5,
    });
    out.id(value.evidence_id.as_bytes());
    out.digest(value.evidence_digest);
    out.i64(value.observed_at_unix_us);
    out.string(&value.authority_revision)?;
    Ok(())
}
pub(in crate::task_run::snapshot) fn get_evidence(
    input: &mut In<'_>,
) -> Result<WakeEvidenceRef, TaskRunSnapshotError> {
    Ok(WakeEvidenceRef {
        cycle_id: CycleId::from_bytes(input.id()?),
        condition_digest: input.digest()?,
        source: match input.u8()? {
            1 => WakeEvidenceSource::ExternalInput,
            2 => WakeEvidenceSource::Approval,
            3 => WakeEvidenceSource::ChildTaskRun,
            4 => WakeEvidenceSource::Timer,
            5 => WakeEvidenceSource::Reconciliation,
            _ => return Err(TaskRunSnapshotError::InvalidEncoding),
        },
        evidence_id: WakeEvidenceId::from_bytes(input.id()?),
        evidence_digest: input.digest()?,
        observed_at_unix_us: input.i64()?,
        authority_revision: input.string()?,
    })
}
pub(in crate::task_run::snapshot) fn put_eval(out: &mut Out, value: &PlanEvaluationRef) {
    out.id(value.evaluation_id.as_bytes());
    out.id(value.taskrun_id.as_bytes());
    out.id(value.plan_id.as_bytes());
    out.u64(value.plan_revision);
    out.u64(value.evaluated_stream_head);
    out.u8(match value.result {
        PlanEvaluationResult::Passed => 1,
        PlanEvaluationResult::Failed => 2,
        PlanEvaluationResult::Blocked => 3,
        PlanEvaluationResult::RequiresReview => 4,
    });
    out.digest(value.gate_definitions_digest);
    out.digest(value.evidence_set_digest);
    out.digest(value.evaluation_digest);
}
pub(in crate::task_run::snapshot) fn get_eval(
    input: &mut In<'_>,
) -> Result<PlanEvaluationRef, TaskRunSnapshotError> {
    Ok(PlanEvaluationRef {
        evaluation_id: PlanEvaluationId::from_bytes(input.id()?),
        taskrun_id: TaskRunId::from_bytes(input.id()?),
        plan_id: PlanId::from_bytes(input.id()?),
        plan_revision: input.u64()?,
        evaluated_stream_head: input.u64()?,
        result: match input.u8()? {
            1 => PlanEvaluationResult::Passed,
            2 => PlanEvaluationResult::Failed,
            3 => PlanEvaluationResult::Blocked,
            4 => PlanEvaluationResult::RequiresReview,
            _ => return Err(TaskRunSnapshotError::InvalidEncoding),
        },
        gate_definitions_digest: input.digest()?,
        evidence_set_digest: input.digest()?,
        evaluation_digest: input.digest()?,
    })
}
