#[test]
fn race_loop_wait_wake_vs_cancellation() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![],
        },
    ));
    let wake_condition = WakeCondition {
        kind: WakeConditionKind::Approval,
        condition_ref: "approval:1".into(),
        condition_digest: digest(11),
    };
    stream.push(envelope(
        8,
        TaskRunEvent::LoopCycleCompleted {
            cycle_id: CYCLE.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            disposition: LoopDisposition::Wait {
                reason: "approval".into(),
                wake_condition: wake_condition.clone(),
            },
        },
    ));
    stream.push(envelope(9, TaskRunEvent::WaitStarted));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Waiting);
    assert!(agg.pending_loop_wait().is_some());
    let before = agg.clone();

    let winner = TaskRunCommand::ResumeLoopWait {
        wake_evidence_ref: WakeEvidenceRef {
            cycle_id: CYCLE.parse().unwrap(),
            condition_digest: digest(11),
            source: WakeEvidenceSource::Approval,
            evidence_id: OTHER.parse().unwrap(),
            evidence_digest: digest(12),
            observed_at_unix_us: 100,
            authority_revision: "approval-v1".into(),
        },
    };
    let loser = TaskRunCommand::RequestCancellation;

    let winner_drafts = agg.decide(winner).unwrap();
    let loser_drafts = agg.decide(loser.clone()).unwrap();
    assert!(!winner_drafts.is_empty());
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert!(after_winner.pending_loop_wait().is_none());
    assert_ne!(after_winner, before);

    // Duplicate wake on already-resumed aggregate → typed error
    let err = after_winner
        .decide(TaskRunCommand::ResumeLoopWait {
            wake_evidence_ref: WakeEvidenceRef {
                cycle_id: CYCLE.parse().unwrap(),
                condition_digest: digest(11),
                source: WakeEvidenceSource::Approval,
                evidence_id: OTHER.parse().unwrap(),
                evidence_digest: digest(13),
                observed_at_unix_us: 200,
                authority_revision: "approval-v2".into(),
            },
        })
        .unwrap_err();
    assert!(
        err.to_string().contains("wait")
            || matches!(
                err,
                DomainError::LoopInvariantViolation { .. } | DomainError::InvalidTransition { .. }
            )
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 3: Retry schedule vs completion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_retry_schedule_vs_completion() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    ));
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
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    let before = agg.clone();

    let step_ref = StepOutcomeRef {
        cycle_id: CYCLE.parse().unwrap(),
        proposal_index: 0,
        step_id: OTHER.parse().unwrap(),
        outcome_digest: digest(13),
    };

    let winner = TaskRunCommand::ScheduleRetry {
        new_attempt_id: ATT2.parse().unwrap(),
        retry_ordinal: 1,
        step_outcome_ref: step_ref.clone(),
        retry_policy_digest: digest(14),
        budget_reservation_ref: budget_ref(),
        delay_ms: 100,
        due_at_unix_us: 100_000,
    };
    let loser = TaskRunCommand::Complete {
        result: TerminalResult::Success,
    };

    let winner_drafts = agg.decide(winner).unwrap();
    let loser_drafts = agg.decide(loser.clone()).unwrap();
    assert!(!winner_drafts.is_empty());
    assert!(!loser_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Retrying);
    assert!(after_winner.pending_retry().is_some());
    assert_ne!(after_winner, before);

    let err = after_winner.decide(loser).unwrap_err();
    assert!(matches!(err, DomainError::InvalidTransition { .. }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 4: Retry activation vs duplicate
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn race_retry_activation_vs_duplicate() {
    let mut stream = base_loop_stream();
    stream.push(envelope(
        6,
        TaskRunEvent::ContextCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            manifest_ref: context_ref(),
        },
    ));
    stream.push(envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0],
        },
    ));
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
    stream.push(envelope(
        9,
        TaskRunEvent::RetryScheduled {
            ordinal: 1,
            old_attempt_id: ATTEMPT.parse().unwrap(),
            new_attempt_id: ATT2.parse().unwrap(),
            abandoned_cycle_id: CYCLE.parse().unwrap(),
            step_outcome_ref: StepOutcomeRef {
                cycle_id: CYCLE.parse().unwrap(),
                proposal_index: 0,
                step_id: OTHER.parse().unwrap(),
                outcome_digest: digest(13),
            },
            retry_policy_digest: digest(14),
            budget_reservation_ref: budget_ref(),
            delay_ms: 25,
            due_at_unix_us: 25_100,
        },
    ));
    let agg = TaskRun::replay(&stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Retrying);
    assert!(agg.pending_retry().is_some());
    let before = agg.clone();

    let winner = TaskRunCommand::ActivateScheduledRetryAttempt {
        retry_ordinal: 1,
        now_unix_us: 25_100,
    };
    let winner_drafts = agg.decide(winner).unwrap();
    assert!(!winner_drafts.is_empty());

    let mut after_winner = agg.clone();
    for draft in &winner_drafts {
        after_winner.apply_payload(draft.payload()).unwrap();
    }
    assert_eq!(after_winner.state(), TaskRunState::Running);
    assert!(after_winner.pending_retry().is_none());
    assert_ne!(after_winner, before);

    let err = after_winner
        .decide(TaskRunCommand::ActivateScheduledRetryAttempt {
            retry_ordinal: 1,
            now_unix_us: 25_200,
        })
        .unwrap_err();
    assert!(matches!(err, DomainError::InvalidTransition { .. }));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Race 5: Recovery resume vs cancellation
// ═══════════════════════════════════════════════════════════════════════════════
