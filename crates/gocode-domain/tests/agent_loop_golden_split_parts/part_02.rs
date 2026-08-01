#[test]
fn loop_checkpoint_digest_roundtrip_and_torn_stream_quarantine() {
    let mut stream = evaluating_stream();
    let checkpoint_id: CheckpointId = OTHER.parse().unwrap();
    let body = LoopCheckpointBody {
        schema_version: "1".into(),
        cycle_id: CYCLE.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        plan_revision_ref: Some(plan_ref(vec![])),
        context_manifest_ref: Some(context_ref()),
        step_outcome_refs: vec![],
    };
    stream.extend([
        envelope(
            8,
            TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position: 8,
                integrity_digest: digest(12),
            },
        ),
        envelope(
            9,
            TaskRunEvent::LoopCheckpointRecorded {
                checkpoint_id,
                event_position: 8,
                body,
                integrity_digest: digest(12),
            },
        ),
        envelope(
            10,
            TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position: 8,
                integrity_digest: digest(12),
            },
        ),
    ]);
    assert!(
        TaskRun::replay(&stream)
            .unwrap()
            .pending_loop_checkpoint()
            .is_none()
    );

    stream.pop();
    assert_eq!(
        TaskRun::replay(&stream).unwrap_err(),
        DomainError::CorruptCommandBatch
    );
}

#[test]
fn retry_replays_committed_timer_and_recovery_replays_checked_generation() {
    let mut retry_stream = evaluating_stream();
    retry_stream[6] = envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    );
    retry_stream.push(envelope(
        8,
        TaskRunEvent::StepOutcomeRecorded {
            cycle_id: CYCLE.parse().unwrap(),
            outcome: StepOutcomeRecord {
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_type: StepOutcomeType::FailedBeforeCommit,
                result_ref: None,
                effect_id: None,
                evidence_digests: vec![],
            },
        },
    ));
    let step_ref = StepOutcomeRef {
        cycle_id: CYCLE.parse().unwrap(),
        proposal_index: 0,
        step_id: OTHER.parse().unwrap(),
        outcome_digest: digest(13),
    };
    retry_stream.extend([
        envelope(
            9,
            TaskRunEvent::RetryScheduled {
                ordinal: 1,
                old_attempt_id: ATTEMPT.parse().unwrap(),
                new_attempt_id: OTHER.parse().unwrap(),
                abandoned_cycle_id: CYCLE.parse().unwrap(),
                step_outcome_ref: step_ref,
                retry_policy_digest: digest(14),
                budget_reservation_ref: budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 25_100,
            },
        ),
        envelope(
            10,
            TaskRunEvent::ActivateScheduledRetryAttempt {
                ordinal: 1,
                attempt_id: OTHER.parse().unwrap(),
                activated_at_unix_us: 25_100,
            },
        ),
    ]);
    let retried = TaskRun::replay(&retry_stream).unwrap();
    assert_eq!(retried.active_attempt(), Some(&OTHER.parse().unwrap()));
    assert!(retried.pending_retry().is_none());

    let mut recovery_stream = evaluating_stream();
    recovery_stream.push(envelope(8, TaskRunEvent::ReconciliationStarted));
    recovery_stream.push(envelope(
        9,
        TaskRunEvent::RecoveryResumeStarted {
            new_attempt_id: OTHER.parse().unwrap(),
            new_generation: 1,
            abandoned_cycle_id: Some(CYCLE.parse().unwrap()),
            context_manifest_ref: context_ref(),
            checkpoint_ref: CheckpointRef {
                checkpoint_id: OTHER.parse().unwrap(),
                event_position: 7,
                integrity_digest: digest(15),
            },
            reconciliation_ref: ReconciliationResultRef {
                reconciliation_run_id: OTHER.parse().unwrap(),
                taskrun_id: TASK.parse().unwrap(),
                predecessor_attempt_id: ATTEMPT.parse().unwrap(),
                recovery_generation: 0,
                reconciled_stream_position: 7,
                status: ReconciliationStatus::Reconciled,
                unresolved_effect_count: 0,
                result_digest: digest(16),
            },
        },
    ));
    let recovered = TaskRun::replay(&recovery_stream).unwrap();
    assert_eq!(recovered.recovery_generation(), 1);
    assert_eq!(recovered.active_attempt(), Some(&OTHER.parse().unwrap()));
}

// ── GATE-P5-002: replay_restores_all_loop_projections ───────────────────

#[test]
fn replay_restores_all_loop_projections() {
    let mut stream = evaluating_stream();
    // Override PlanCommitted with non-empty indexes so cycle stays in Acting.
    stream[6] = envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    );
    stream.extend([
        envelope(
            8,
            TaskRunEvent::StepOutcomeRecorded {
                cycle_id: CYCLE.parse().unwrap(),
                outcome: StepOutcomeRecord {
                    proposal_index: 0,
                    step_id: OTHER.parse().unwrap(),
                    outcome_type: StepOutcomeType::Succeeded,
                    result_ref: Some(
                        ResultRef::new(
                            OTHER.parse().unwrap(),
                            "application/octet-stream",
                            digest(11),
                        )
                        .unwrap(),
                    ),
                    effect_id: None,
                    evidence_digests: vec![],
                },
            },
        ),
        envelope(
            9,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Continue,
            },
        ),
        envelope(
            10,
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id: CYCLE.parse().unwrap(),
                successor_cycle_id: SUCCESSOR.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                sequence: 1,
            },
        ),
        envelope(
            11,
            TaskRunEvent::LoopCycleStarted {
                cycle_id: SUCCESSOR.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                sequence: 1,
                parent_cycle_id: Some(CYCLE.parse().unwrap()),
            },
        ),
    ]);
    let agg = TaskRun::replay(&stream).unwrap();
    // active_cycle — successor cycle consuming pending_successor
    let active = agg.active_cycle().unwrap();
    assert_eq!(active.cycle_id, SUCCESSOR.parse().unwrap());
    assert_eq!(active.sequence, 1);
    assert_eq!(active.parent_cycle_id, Some(CYCLE.parse().unwrap()));
    // last_completed_cycle — first cycle
    let completed = agg.last_completed_cycle().unwrap();
    assert_eq!(completed.cycle_id, CYCLE.parse().unwrap());
    assert_eq!(completed.sequence, 0);
    assert!(completed.successor_allocated);
    // cycle_history — 2 entries
    assert_eq!(agg.cycle_history().len(), 2);
    assert_eq!(agg.cycle_history()[0].cycle_id, CYCLE.parse().unwrap());
    assert_eq!(agg.cycle_history()[0].sequence, 0);
    assert_eq!(agg.cycle_history()[1].cycle_id, SUCCESSOR.parse().unwrap());
    assert_eq!(agg.cycle_history()[1].sequence, 1);
    // pending_successor — consumed
    assert!(agg.pending_successor().is_none());
}

// ── GATE-P5-004: successor_requires_exact_reservation ───────────────────
