#[test]
fn loop_event_sensitivity_is_exact_except_declared_dual_failure() {
    use crate::{
        context::ContextManifestRef,
        event::Sensitivity,
        id::{
            AttemptId, BudgetReservationId, ContextManifestId, CycleId, IntegrityDigest, PlanId,
            ResultId, TaskRunId,
        },
        plan::PlanRevisionRef,
        reference::{BudgetReservationRef, ResultRef},
        task_run::TaskRunEvent,
    };

    let digest = IntegrityDigest::from_bytes([4; 32]);
    let context = ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes([1; 16]),
        taskrun_id: TaskRunId::from_bytes([2; 16]),
        attempt_id: AttemptId::from_bytes([3; 16]),
        cycle_id: CycleId::from_bytes([5; 16]),
        revision: 1,
        policy_revision: "test".into(),
        integrity_digest: digest,
    };
    let context_event = TaskRunEvent::ContextCommitted {
        cycle_id: context.cycle_id,
        manifest_ref: context.clone(),
    };
    assert!(context_event.accepts_sensitivity(Sensitivity::Sensitive));
    assert!(!context_event.accepts_sensitivity(Sensitivity::Public));

    let plan_event = TaskRunEvent::PlanCommitted {
        cycle_id: context.cycle_id,
        plan_revision_ref: PlanRevisionRef {
            plan_id: PlanId::from_bytes([6; 16]),
            taskrun_id: context.taskrun_id,
            cycle_id: context.cycle_id,
            revision: 1,
            context_manifest_ref: context,
            expected_proposal_indexes: vec![0],
            proposal_batch_digest: digest,
            planning_policy_ref: ResultRef::new(
                ResultId::from_bytes([7; 16]),
                "application/test",
                digest,
            )
            .unwrap(),
            planning_budget_ref: BudgetReservationRef {
                reservation_id: BudgetReservationId::from_bytes([8; 16]),
                taskrun_id: TaskRunId::from_bytes([2; 16]),
                attempt_id: AttemptId::from_bytes([3; 16]),
                retry_ordinal: 0,
                reservation_digest: digest,
            },
            parent_ref: None,
            integrity_digest: digest,
        },
        input_digest: digest,
        output_digest: digest,
        expected_proposal_indexes: vec![0],
    };
    assert!(plan_event.accepts_sensitivity(Sensitivity::Sensitive));
    assert!(!plan_event.accepts_sensitivity(Sensitivity::Public));

    let failed = TaskRunEvent::TaskRunFailed {
        reason: "fixture".into(),
    };
    assert!(failed.accepts_sensitivity(Sensitivity::Public));
    assert!(failed.accepts_sensitivity(Sensitivity::Sensitive));
}
