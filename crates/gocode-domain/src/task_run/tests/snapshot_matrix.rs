#[test]
fn closed_snapshot_round_trips_all_active_cycle_states_and_outcome_kinds() {
    assert_snapshot_round_trip(snapshot_active(LoopCycleState::Observing, vec![], None));
    assert_snapshot_round_trip(snapshot_active(LoopCycleState::Proposing, vec![], None));
    assert_snapshot_round_trip(snapshot_active(
        LoopCycleState::Acting,
        vec![],
        Some(PlanParentRef {
            plan_id: snapshot_id::<PlanId>(SNAPSHOT_PLAN),
            revision: 2,
            integrity_digest: snapshot_digest(25),
        }),
    ));
    assert_snapshot_round_trip(snapshot_active(
        LoopCycleState::Evaluating,
        vec![
            snapshot_outcome(
                0,
                StepOutcomeType::Succeeded,
                Some(snapshot_result()),
                Some(snapshot_id::<EffectId>(SNAPSHOT_EFFECT)),
            ),
            snapshot_outcome(1, StepOutcomeType::FailedBeforeCommit, None, None),
            snapshot_outcome(
                2,
                StepOutcomeType::FailedAfterCommit,
                Some(snapshot_result()),
                Some(snapshot_id::<EffectId>(SNAPSHOT_EFFECT)),
            ),
            snapshot_outcome(
                3,
                StepOutcomeType::Uncertain,
                None,
                Some(snapshot_id::<EffectId>(SNAPSHOT_EFFECT)),
            ),
            snapshot_outcome(4, StepOutcomeType::Cancelled, Some(snapshot_result()), None),
        ],
        None,
    ));
}

#[test]
fn closed_snapshot_round_trips_every_wake_kind_and_evidence_source() {
    let kinds = [
        WakeConditionKind::ExternalInput,
        WakeConditionKind::Approval,
        WakeConditionKind::ChildTaskRun,
        WakeConditionKind::Timer,
        WakeConditionKind::Reconciliation,
    ];
    let sources = [
        WakeEvidenceSource::ExternalInput,
        WakeEvidenceSource::Approval,
        WakeEvidenceSource::ChildTaskRun,
        WakeEvidenceSource::Timer,
        WakeEvidenceSource::Reconciliation,
    ];
    for (kind, source) in kinds.into_iter().zip(sources) {
        let mut aggregate = snapshot_running();
        let cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CYCLE);
        aggregate.cycle_history = vec![snapshot_history(cycle_id, 0, None)];
        aggregate.last_completed_cycle = Some(CompletedCycleRef {
            cycle_id,
            attempt_id: snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT),
            sequence: 0,
            disposition: LoopDisposition::Wait {
                reason: "wait".into(),
                wake_condition: snapshot_wake(kind),
            },
            accepted_wake_evidence: Some(snapshot_evidence(source, cycle_id)),
            successor_allocated: true,
        });
        assert_snapshot_round_trip(aggregate);
    }
}

#[test]
fn closed_snapshot_round_trips_passed_plan_evaluation_and_rejects_other_results() {
    for result in [
        PlanEvaluationResult::Passed,
        PlanEvaluationResult::Failed,
        PlanEvaluationResult::Blocked,
        PlanEvaluationResult::RequiresReview,
    ] {
        let mut aggregate = snapshot_running();
        let cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CYCLE);
        aggregate.cycle_history = vec![snapshot_history(cycle_id, 0, None)];
        aggregate.last_completed_cycle = Some(CompletedCycleRef {
            cycle_id,
            attempt_id: snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT),
            sequence: 0,
            disposition: LoopDisposition::Complete {
                plan_evaluation_ref: snapshot_evaluation(result),
            },
            accepted_wake_evidence: None,
            successor_allocated: false,
        });
        if result == PlanEvaluationResult::Passed {
            assert_snapshot_round_trip(aggregate);
        } else {
            assert_eq!(
                aggregate.snapshot_v1().encode(),
                Err(TaskRunSnapshotError::InvalidState)
            );
        }
    }
}

#[test]
fn closed_snapshot_round_trips_pending_successor_wait_retry_and_checkpoint_states() {
    let taskrun_id = snapshot_id::<TaskRunId>(SNAPSHOT_TASKRUN);
    let attempt_id = snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT);
    let cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CYCLE);
    let child_cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CHILD_CYCLE);
    let completed = CompletedCycleRef {
        cycle_id,
        attempt_id,
        sequence: 0,
        disposition: LoopDisposition::Continue,
        accepted_wake_evidence: None,
        successor_allocated: true,
    };
    let mut successor = snapshot_running();
    successor.cycle_history = vec![snapshot_history(cycle_id, 0, None)];
    successor.last_completed_cycle = Some(completed);
    successor.pending_successor = Some(PendingSuccessorCycle {
        parent_cycle_id: cycle_id,
        successor_cycle_id: child_cycle_id,
        attempt_id,
        sequence: 1,
    });
    assert_snapshot_round_trip(successor);

    let wake = snapshot_wake(WakeConditionKind::Approval);
    let mut waiting = snapshot_running();
    waiting.state = TaskRunState::Waiting;
    waiting.cycle_history = vec![snapshot_history(cycle_id, 0, None)];
    waiting.last_completed_cycle = Some(CompletedCycleRef {
        cycle_id,
        attempt_id,
        sequence: 0,
        disposition: LoopDisposition::Wait {
            reason: "approval".into(),
            wake_condition: wake.clone(),
        },
        accepted_wake_evidence: None,
        successor_allocated: false,
    });
    waiting.pending_loop_wait = Some(PendingLoopWait {
        cycle_id,
        wake_condition: wake,
    });
    assert_snapshot_round_trip(waiting);

    let mut retry = snapshot_running();
    retry.state = TaskRunState::Retrying;
    retry.cycle_history = vec![snapshot_history(cycle_id, 0, None)];
    retry.pending_retry = Some(PendingRetry {
        ordinal: 3,
        old_attempt_id: attempt_id,
        new_attempt_id: snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT_NEXT),
        abandoned_cycle_id: cycle_id,
        step_outcome_ref: StepOutcomeRef {
            cycle_id,
            proposal_index: 4,
            step_id: snapshot_id::<StepId>(SNAPSHOT_STEP),
            outcome_digest: snapshot_digest(26),
        },
        due_at_unix_us: -9,
        delay_ms: 5,
        budget_reservation_ref: BudgetReservationRef {
            reservation_id: snapshot_id::<BudgetReservationId>(SNAPSHOT_BUDGET),
            taskrun_id,
            attempt_id,
            retry_ordinal: 3,
            reservation_digest: snapshot_digest(27),
        },
        retry_policy_digest: snapshot_digest(28),
    });
    assert_snapshot_round_trip(retry);

    for recorded_integrity_digest in [None, Some(snapshot_digest(29))] {
        let mut checkpoint = snapshot_running();
        checkpoint.pending_loop_checkpoint = Some(PendingLoopCheckpoint {
            checkpoint_id: snapshot_id::<CheckpointId>(SNAPSHOT_CHECKPOINT),
            start_position: 45,
            expected_integrity_digest: snapshot_digest(29),
            recorded_integrity_digest,
        });
        assert_eq!(
            checkpoint.snapshot_v1().encode(),
            Err(TaskRunSnapshotError::InvalidState)
        );
    }
}
