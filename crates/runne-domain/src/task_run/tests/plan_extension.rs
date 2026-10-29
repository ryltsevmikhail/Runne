#[test]
fn plan_extension_appends_after_settlement_and_rejects_parent_or_scope_changes() {
    use crate::{
        agent_loop::LoopCycleState,
        context::ContextManifestRef,
        plan::{PlanParentRef, PlanRevisionRef},
        reference::{BudgetReservationRef, ResultRef},
    };
    let mut task = running_aggregate();
    let cycle_id = WORKSPACE_ID.parse().unwrap();
    task.apply_payload(&TaskRunEvent::LoopCycleStarted {
        cycle_id,
        attempt_id: ATTEMPT_ID.parse().unwrap(),
        sequence: 0,
        parent_cycle_id: None,
    })
    .unwrap();
    let digest = IntegrityDigest::from_bytes([7; 32]);
    let context = ContextManifestRef {
        manifest_id: WORKSPACE_ID.parse().unwrap(),
        taskrun_id: task.id,
        attempt_id: ATTEMPT_ID.parse().unwrap(),
        cycle_id,
        revision: 1,
        policy_revision: "coding-v1".into(),
        integrity_digest: digest,
    };
    task.apply_payload(&TaskRunEvent::ContextCommitted {
        cycle_id,
        manifest_ref: context.clone(),
    })
    .unwrap();
    let base = PlanRevisionRef {
        plan_id: WORKSPACE_ID.parse().unwrap(),
        taskrun_id: task.id,
        cycle_id,
        revision: 1,
        context_manifest_ref: context,
        expected_proposal_indexes: vec![],
        proposal_batch_digest: digest,
        planning_policy_ref: ResultRef::new(
            WORKSPACE_ID.parse().unwrap(),
            "application/json",
            digest,
        )
        .unwrap(),
        planning_budget_ref: BudgetReservationRef {
            reservation_id: WORKSPACE_ID.parse().unwrap(),
            taskrun_id: task.id,
            attempt_id: ATTEMPT_ID.parse().unwrap(),
            retry_ordinal: 0,
            reservation_digest: digest,
        },
        parent_ref: None,
        integrity_digest: digest,
    };
    let event = |plan: PlanRevisionRef| TaskRunEvent::PlanCommitted {
        cycle_id,
        input_digest: plan.context_manifest_ref.integrity_digest,
        output_digest: plan.integrity_digest,
        expected_proposal_indexes: plan.expected_proposal_indexes.clone(),
        plan_revision_ref: plan,
    };
    task.apply_payload(&event(base.clone())).unwrap();
    assert_eq!(
        task.active_cycle.as_ref().unwrap().state,
        LoopCycleState::Evaluating
    );
    let mut next = base.clone();
    next.revision = 2;
    next.expected_proposal_indexes = vec![0];
    next.parent_ref = Some(PlanParentRef {
        plan_id: base.plan_id,
        revision: base.revision,
        integrity_digest: base.integrity_digest,
    });
    next.integrity_digest = IntegrityDigest::from_bytes([8; 32]);
    for kind in 0..4 {
        let mut bad = next.clone();
        match kind {
            0 => bad.parent_ref = None,
            1 => bad.expected_proposal_indexes = vec![1],
            2 => bad.planning_budget_ref.reservation_digest = IntegrityDigest::from_bytes([9; 32]),
            _ => bad.context_manifest_ref.revision += 1,
        };
        let mut copy = task.clone();
        assert!(copy.apply_payload(&event(bad)).is_err());
        assert_eq!(copy, task);
    }
    task.apply_payload(&event(next.clone())).unwrap();
    assert_eq!(
        task.active_cycle.as_ref().unwrap().state,
        LoopCycleState::Acting
    );
    let before = task.clone();
    assert!(task.apply_payload(&event(next.clone())).is_err());
    assert_eq!(before, task);
    task.apply_payload(&TaskRunEvent::StepOutcomeRecorded {
        cycle_id,
        outcome: crate::agent_loop::StepOutcomeRecord {
            proposal_index: 0,
            step_id: WORKSPACE_ID.parse().unwrap(),
            outcome_type: crate::agent_loop::StepOutcomeType::Succeeded,
            result_ref: Some(
                ResultRef::new(WORKSPACE_ID.parse().unwrap(), "application/json", digest).unwrap(),
            ),
            effect_id: Some(WORKSPACE_ID.parse().unwrap()),
            evidence_digests: vec![digest],
        },
    })
    .unwrap();
    let mut third = next.clone();
    third.revision += 1;
    third.expected_proposal_indexes.push(1);
    third.parent_ref = Some(PlanParentRef {
        plan_id: next.plan_id,
        revision: next.revision,
        integrity_digest: next.integrity_digest,
    });
    third.integrity_digest = IntegrityDigest::from_bytes([10; 32]);
    let mut rewritten = third.clone();
    rewritten.expected_proposal_indexes = vec![1, 2];
    assert!(task.apply_payload(&event(rewritten)).is_err());
    task.apply_payload(&event(third)).unwrap();
    assert_eq!(
        task.active_cycle.as_ref().unwrap().recorded_outcomes.len(),
        1
    );
    let encoded = task.snapshot_v1().encode().unwrap();
    assert_eq!(
        TaskRunSnapshotV1::decode(&encoded).unwrap(),
        task.snapshot_v1()
    );
}
