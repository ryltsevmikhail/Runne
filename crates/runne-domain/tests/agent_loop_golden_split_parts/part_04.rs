#[test]
fn invalid_event_preserves_state() {
    // Replay with an attempt_id mismatch in LoopCycleStarted.
    let mut stream = evaluating_stream();
    stream.push(envelope(
        8,
        TaskRunEvent::LoopCycleStarted {
            cycle_id: CYCLE.parse().unwrap(),
            // attempt_id doesn't match active_attempt (which is ATTEMPT).
            attempt_id: OTHER.parse().unwrap(),
            sequence: 0,
            parent_cycle_id: None,
        },
    ));
    let err = TaskRun::replay(&stream).unwrap_err();
    assert!(matches!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::MissingActiveAttempt
        }
    ));
}

// ── GATE-P5-015: activation_time_comes_only_from_time_port ─────────────

#[test]
fn activation_time_comes_only_from_time_port() {
    let mut stream = evaluating_stream();
    // Override PlanCommitted with indexes [0] so we can record outcome.
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
    stream.push(envelope(
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
    stream.push(envelope(
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
            due_at_unix_us: 1000,
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Retrying);
    assert!(agg.pending_retry().is_some());
    // Activate with activated_at_unix_us=500 (< due_at_unix_us=1000) is rejected.
    let err = agg
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 1,
            now_unix_us: 500,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::RetryNotDue
        }
    ));
}

// ── GATE-P5-018: only_current_passed_is_accepted ───────────────────────

#[test]
fn only_current_passed_is_accepted() {
    let mut stream = evaluating_stream();
    // Plan with indexes [0] → moves to Acting.
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
    // Record outcome → moves to Evaluating.
    stream.push(envelope(
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
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    // LoopCycleCompleted(Complete) with Failed evaluation is rejected.
    let failed_eval = PlanEvaluationRef {
        evaluation_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        plan_id: OTHER.parse().unwrap(),
        plan_revision: 1,
        evaluated_stream_head: 8,
        result: PlanEvaluationResult::Failed,
        gate_definitions_digest: digest(6),
        evidence_set_digest: digest(7),
        evaluation_digest: digest(8),
    };
    let err = agg
        .decide(TaskRunCommand::CompleteLoopCycle {
            cycle_id: CYCLE.parse().unwrap(),
            disposition: LoopDisposition::Complete {
                plan_evaluation_ref: failed_eval,
            },
        })
        .unwrap_err();
    assert!(matches!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::PlanBindingMismatch
        }
    ));
}
