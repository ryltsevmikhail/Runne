use crate::agent_loop::{
    ActiveLoopCycle, CompletedCycleRef, CycleHistoryEntry, LoopCycleState, LoopDisposition,
    StepOutcomeRecord, StepOutcomeType, WakeCondition, WakeConditionKind, WakeEvidenceRef,
    WakeEvidenceSource,
};
use crate::context::ContextManifestRef;
use crate::id::{
    AttemptId, BudgetReservationId, CheckpointId, ContextManifestId, CycleId, EffectId,
    IntegrityDigest, PlanEvaluationId, PlanId, ResultId, StepId, TaskRunId, WakeEvidenceId,
};
use crate::plan::{PlanParentRef, PlanRevisionRef};
use crate::reference::{BudgetReservationRef, ResultRef};
use crate::verification::{PlanEvaluationRef, PlanEvaluationResult};

const SNAPSHOT_TASKRUN: &str = "018f2e3a-7000-7000-8000-000000000010";
const SNAPSHOT_ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000011";
const SNAPSHOT_ATTEMPT_NEXT: &str = "018f2e3a-7000-7000-8000-000000000012";
const SNAPSHOT_CYCLE: &str = "018f2e3a-7000-7000-8000-000000000013";
const SNAPSHOT_CHILD_CYCLE: &str = "018f2e3a-7000-7000-8000-000000000014";
const SNAPSHOT_MANIFEST: &str = "018f2e3a-7000-7000-8000-000000000015";
const SNAPSHOT_PLAN: &str = "018f2e3a-7000-7000-8000-000000000016";
const SNAPSHOT_RESULT: &str = "018f2e3a-7000-7000-8000-000000000017";
const SNAPSHOT_BUDGET: &str = "018f2e3a-7000-7000-8000-000000000018";
const SNAPSHOT_STEP: &str = "018f2e3a-7000-7000-8000-000000000019";
const SNAPSHOT_EFFECT: &str = "018f2e3a-7000-7000-8000-000000000020";
const SNAPSHOT_EVALUATION: &str = "018f2e3a-7000-7000-8000-000000000021";
const SNAPSHOT_EVIDENCE: &str = "018f2e3a-7000-7000-8000-000000000022";
const SNAPSHOT_CHECKPOINT: &str = "018f2e3a-7000-7000-8000-000000000023";

fn snapshot_id<T>(value: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn snapshot_digest(value: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([value; 32])
}

fn snapshot_result() -> ResultRef {
    ResultRef::new(
        snapshot_id::<ResultId>(SNAPSHOT_RESULT),
        "application/json",
        snapshot_digest(1),
    )
    .unwrap()
}

fn snapshot_context(
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    cycle_id: CycleId,
) -> ContextManifestRef {
    ContextManifestRef {
        manifest_id: snapshot_id::<ContextManifestId>(SNAPSHOT_MANIFEST),
        taskrun_id,
        attempt_id,
        cycle_id,
        revision: 3,
        policy_revision: "context-v3".into(),
        integrity_digest: snapshot_digest(2),
    }
}

fn snapshot_plan(
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    cycle_id: CycleId,
    indexes: Vec<u32>,
    parent_ref: Option<PlanParentRef>,
) -> PlanRevisionRef {
    PlanRevisionRef {
        plan_id: snapshot_id::<PlanId>(SNAPSHOT_PLAN),
        taskrun_id,
        cycle_id,
        revision: 4,
        context_manifest_ref: snapshot_context(taskrun_id, attempt_id, cycle_id),
        expected_proposal_indexes: indexes,
        proposal_batch_digest: snapshot_digest(3),
        planning_policy_ref: snapshot_result(),
        planning_budget_ref: BudgetReservationRef {
            reservation_id: snapshot_id::<BudgetReservationId>(SNAPSHOT_BUDGET),
            taskrun_id,
            attempt_id,
            retry_ordinal: 0,
            reservation_digest: snapshot_digest(4),
        },
        parent_ref,
        integrity_digest: snapshot_digest(5),
    }
}

fn snapshot_outcome(
    proposal_index: u32,
    outcome_type: StepOutcomeType,
    result_ref: Option<ResultRef>,
    effect_id: Option<EffectId>,
) -> StepOutcomeRecord {
    let step_id = match proposal_index {
        0 => SNAPSHOT_STEP,
        1 => SNAPSHOT_EFFECT,
        2 => SNAPSHOT_EVALUATION,
        3 => SNAPSHOT_EVIDENCE,
        _ => SNAPSHOT_CHECKPOINT,
    };
    StepOutcomeRecord {
        proposal_index,
        step_id: snapshot_id::<StepId>(step_id),
        outcome_type,
        result_ref,
        effect_id,
        evidence_digests: vec![snapshot_digest(proposal_index as u8 + 10)],
    }
}

fn snapshot_history(
    cycle_id: CycleId,
    sequence: u64,
    parent_cycle_id: Option<CycleId>,
) -> CycleHistoryEntry {
    CycleHistoryEntry {
        cycle_id,
        attempt_id: snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT),
        sequence,
        parent_cycle_id,
    }
}

fn snapshot_wake(kind: WakeConditionKind) -> WakeCondition {
    WakeCondition {
        kind,
        condition_ref: "wake-condition-v1".into(),
        condition_digest: snapshot_digest(20),
    }
}

fn snapshot_evidence(source: WakeEvidenceSource, cycle_id: CycleId) -> WakeEvidenceRef {
    WakeEvidenceRef {
        cycle_id,
        condition_digest: snapshot_digest(20),
        source,
        evidence_id: snapshot_id::<WakeEvidenceId>(SNAPSHOT_EVIDENCE),
        evidence_digest: snapshot_digest(21),
        observed_at_unix_us: 88,
        authority_revision: "authority-v2".into(),
    }
}

fn snapshot_evaluation(result: PlanEvaluationResult) -> PlanEvaluationRef {
    PlanEvaluationRef {
        evaluation_id: snapshot_id::<PlanEvaluationId>(SNAPSHOT_EVALUATION),
        taskrun_id: snapshot_id::<TaskRunId>(SNAPSHOT_TASKRUN),
        plan_id: snapshot_id::<PlanId>(SNAPSHOT_PLAN),
        plan_revision: 4,
        evaluated_stream_head: 99,
        result,
        gate_definitions_digest: snapshot_digest(22),
        evidence_set_digest: snapshot_digest(23),
        evaluation_digest: snapshot_digest(24),
    }
}

fn snapshot_active(
    state: LoopCycleState,
    outcomes: Vec<StepOutcomeRecord>,
    parent_ref: Option<PlanParentRef>,
) -> TaskRun {
    let taskrun_id = snapshot_id::<TaskRunId>(SNAPSHOT_TASKRUN);
    let attempt_id = snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT);
    let cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CYCLE);
    let indexes = if state == LoopCycleState::Acting && outcomes.is_empty() {
        vec![0]
    } else {
        (0..outcomes.len() as u32).collect()
    };
    let context = snapshot_context(taskrun_id, attempt_id, cycle_id);
    let plan = snapshot_plan(
        taskrun_id,
        attempt_id,
        cycle_id,
        indexes.clone(),
        parent_ref,
    );
    let (context_manifest_ref, plan_revision_ref, expected_proposal_indexes, recorded_outcomes) =
        match state {
            LoopCycleState::Observing => (None, None, vec![], vec![]),
            LoopCycleState::Proposing => (Some(context), None, vec![], vec![]),
            LoopCycleState::Acting | LoopCycleState::Evaluating => (
                Some(plan.context_manifest_ref.clone()),
                Some(plan),
                indexes,
                outcomes,
            ),
            LoopCycleState::Completed => unreachable!("completed cycles are not active"),
        };
    TaskRun {
        id: taskrun_id,
        state: TaskRunState::Running,
        active_attempt: Some(attempt_id),
        attempt_history: vec![attempt_id],
        terminal_result: None,
        active_cycle: Some(ActiveLoopCycle {
            cycle_id,
            attempt_id,
            sequence: 0,
            parent_cycle_id: None,
            state,
            context_manifest_ref,
            plan_revision_ref,
            expected_proposal_indexes,
            recorded_outcomes,
        }),
        last_completed_cycle: None,
        pending_successor: None,
        pending_loop_wait: None,
        pending_retry: None,
        pending_loop_checkpoint: None,
        cycle_history: vec![snapshot_history(cycle_id, 0, None)],
        recovery_generation: 0,
    }
}

fn snapshot_running() -> TaskRun {
    let taskrun_id = snapshot_id::<TaskRunId>(SNAPSHOT_TASKRUN);
    let attempt_id = snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT);
    TaskRun {
        id: taskrun_id,
        state: TaskRunState::Running,
        active_attempt: Some(attempt_id),
        attempt_history: vec![attempt_id],
        terminal_result: None,
        active_cycle: None,
        last_completed_cycle: None,
        pending_successor: None,
        pending_loop_wait: None,
        pending_retry: None,
        pending_loop_checkpoint: None,
        cycle_history: vec![],
        recovery_generation: 0,
    }
}

fn assert_snapshot_round_trip(aggregate: TaskRun) {
    let encoded = aggregate
        .snapshot_v1()
        .encode()
        .unwrap_or_else(|error| panic!("encode {aggregate:?}: {error:?}"));
    let snapshot = TaskRunSnapshotV1::decode(&encoded)
        .unwrap_or_else(|error| panic!("decode {aggregate:?}: {error:?}"));
    assert_eq!(snapshot, aggregate.snapshot_v1());
}
