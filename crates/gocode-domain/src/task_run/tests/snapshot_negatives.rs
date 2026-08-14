#[test]
fn closed_snapshot_rejects_invalid_active_history_plan_and_context_bindings() {
    let mut missing_history = snapshot_active(LoopCycleState::Observing, vec![], None);
    missing_history.cycle_history.clear();
    assert_eq!(
        missing_history.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut wrong_plan = snapshot_active(LoopCycleState::Acting, vec![], None);
    wrong_plan
        .active_cycle
        .as_mut()
        .unwrap()
        .plan_revision_ref
        .as_mut()
        .unwrap()
        .taskrun_id = snapshot_id::<TaskRunId>(SNAPSHOT_CHILD_CYCLE);
    assert_eq!(
        wrong_plan.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut wrong_context = snapshot_active(LoopCycleState::Acting, vec![], None);
    wrong_context
        .active_cycle
        .as_mut()
        .unwrap()
        .context_manifest_ref
        .as_mut()
        .unwrap()
        .attempt_id = snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT_NEXT);
    wrong_context
        .active_cycle
        .as_mut()
        .unwrap()
        .plan_revision_ref
        .as_mut()
        .unwrap()
        .context_manifest_ref = wrong_context
        .active_cycle
        .as_ref()
        .unwrap()
        .context_manifest_ref
        .clone()
        .unwrap();
    assert_eq!(
        wrong_context.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );
}

#[test]
fn closed_snapshot_rejects_duplicate_and_cyclic_projection_indexes() {
    let outcome = snapshot_outcome(0, StepOutcomeType::Succeeded, Some(snapshot_result()), None);
    let mut duplicate_outcome = snapshot_active(
        LoopCycleState::Evaluating,
        vec![outcome.clone(), outcome],
        None,
    );
    duplicate_outcome
        .active_cycle
        .as_mut()
        .unwrap()
        .expected_proposal_indexes = vec![0, 1];
    assert_eq!(
        duplicate_outcome.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut duplicate_indexes = snapshot_active(LoopCycleState::Acting, vec![], None);
    duplicate_indexes
        .active_cycle
        .as_mut()
        .unwrap()
        .expected_proposal_indexes = vec![0, 0];
    duplicate_indexes
        .active_cycle
        .as_mut()
        .unwrap()
        .plan_revision_ref
        .as_mut()
        .unwrap()
        .expected_proposal_indexes = vec![0, 0];
    assert_eq!(
        duplicate_indexes.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut invalid_history = snapshot_running();
    let cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CYCLE);
    let child_cycle_id = snapshot_id::<CycleId>(SNAPSHOT_CHILD_CYCLE);
    invalid_history.cycle_history = vec![
        snapshot_history(cycle_id, 1, Some(child_cycle_id)),
        snapshot_history(child_cycle_id, 2, Some(cycle_id)),
    ];
    assert_eq!(
        invalid_history.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );
}

#[test]
fn closed_snapshot_rejects_pre_attempt_history_and_mismatched_checkpoint_record() {
    let mut pre_attempt = snapshot_running();
    pre_attempt.state = TaskRunState::Admitted;
    pre_attempt.active_attempt = None;
    pre_attempt.attempt_history.clear();
    pre_attempt.cycle_history = vec![snapshot_history(
        snapshot_id::<CycleId>(SNAPSHOT_CYCLE),
        0,
        None,
    )];
    assert_eq!(
        pre_attempt.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut mismatched_checkpoint = snapshot_running();
    mismatched_checkpoint.pending_loop_checkpoint = Some(PendingLoopCheckpoint {
        checkpoint_id: snapshot_id::<CheckpointId>(SNAPSHOT_CHECKPOINT),
        start_position: 0,
        expected_integrity_digest: snapshot_digest(30),
        recorded_integrity_digest: Some(snapshot_digest(31)),
    });
    assert_eq!(
        mismatched_checkpoint.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut fabricated_recovery_generation = snapshot_running();
    fabricated_recovery_generation.recovery_generation = 1;
    assert_eq!(
        fabricated_recovery_generation.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );
}

#[test]
fn closed_snapshot_rejects_every_impossible_lifecycle_attempt_cardinality() {
    for state in [
        TaskRunState::Created,
        TaskRunState::Queued,
        TaskRunState::Admitted,
    ] {
        let mut value = snapshot_running();
        value.state = state;
        value.active_attempt = None;
        assert_eq!(
            value.snapshot_v1().encode(),
            Err(TaskRunSnapshotError::InvalidState),
            "{state:?} cannot retain an attempt"
        );
    }
    for state in [
        TaskRunState::Running,
        TaskRunState::Waiting,
        TaskRunState::Retrying,
        TaskRunState::Checkpointing,
        TaskRunState::Reconciling,
    ] {
        let mut value = snapshot_running();
        value.state = state;
        value.active_attempt = None;
        value.attempt_history.clear();
        assert_eq!(
            value.snapshot_v1().encode(),
            Err(TaskRunSnapshotError::InvalidState),
            "{state:?} requires an active latest attempt"
        );
    }
    for state in [
        TaskRunState::Succeeded,
        TaskRunState::Failed,
        TaskRunState::BudgetExhausted,
        TaskRunState::PolicyDenied,
        TaskRunState::Unrecoverable,
    ] {
        let mut value = snapshot_running();
        value.state = state;
        value.active_attempt = None;
        value.attempt_history.clear();
        value.terminal_result = (state == TaskRunState::Succeeded).then_some(TerminalResult::Success);
        assert_eq!(
            value.snapshot_v1().encode(),
            Err(TaskRunSnapshotError::InvalidState),
            "{state:?} cannot terminally complete before an attempt"
        );
    }
    let mut cancelled = snapshot_running();
    cancelled.state = TaskRunState::Cancelled;
    assert_eq!(
        cancelled.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState),
        "cancelled snapshots cannot retain an active attempt"
    );
}

#[test]
fn closed_snapshot_rejects_noncanonical_cycle_epochs_and_parent_order() {
    let attempt = snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT);
    let next_attempt = snapshot_id::<AttemptId>(SNAPSHOT_ATTEMPT_NEXT);
    let root = snapshot_id::<CycleId>(SNAPSHOT_CYCLE);
    let child = snapshot_id::<CycleId>(SNAPSHOT_CHILD_CYCLE);

    let mut child_before_parent = snapshot_running();
    child_before_parent.cycle_history = vec![
        CycleHistoryEntry {
            cycle_id: child,
            attempt_id: attempt,
            sequence: 1,
            parent_cycle_id: Some(root),
        },
        CycleHistoryEntry {
            cycle_id: root,
            attempt_id: attempt,
            sequence: 0,
            parent_cycle_id: None,
        },
    ];
    assert_eq!(
        child_before_parent.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut non_immediate_parent = snapshot_running();
    non_immediate_parent.cycle_history = vec![
        CycleHistoryEntry {
            cycle_id: root,
            attempt_id: attempt,
            sequence: 0,
            parent_cycle_id: None,
        },
        CycleHistoryEntry {
            cycle_id: child,
            attempt_id: attempt,
            sequence: 1,
            parent_cycle_id: Some(root),
        },
        CycleHistoryEntry {
            cycle_id: snapshot_id::<CycleId>(SNAPSHOT_MANIFEST),
            attempt_id: attempt,
            sequence: 2,
            parent_cycle_id: Some(root),
        },
    ];
    assert_eq!(
        non_immediate_parent.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut interleaved_epochs = snapshot_running();
    interleaved_epochs.attempt_history.push(next_attempt);
    interleaved_epochs.active_attempt = Some(next_attempt);
    interleaved_epochs.cycle_history = vec![
        CycleHistoryEntry {
            cycle_id: root,
            attempt_id: attempt,
            sequence: 0,
            parent_cycle_id: None,
        },
        CycleHistoryEntry {
            cycle_id: child,
            attempt_id: next_attempt,
            sequence: 0,
            parent_cycle_id: None,
        },
        CycleHistoryEntry {
            cycle_id: snapshot_id::<CycleId>(SNAPSHOT_MANIFEST),
            attempt_id: attempt,
            sequence: 1,
            parent_cycle_id: Some(root),
        },
    ];
    assert_eq!(
        interleaved_epochs.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );
}
