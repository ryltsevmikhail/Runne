#[test]
fn successor_requires_exact_reservation() {
    let mut stream = evaluating_stream();
    stream.extend([
        envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Continue,
            },
        ),
        envelope(
            9,
            TaskRunEvent::NextCycleCreated {
                parent_cycle_id: CYCLE.parse().unwrap(),
                successor_cycle_id: SUCCESSOR.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                sequence: 1,
            },
        ),
    ]);
    let agg = TaskRun::replay(&stream).unwrap();
    assert!(agg.pending_successor().is_some());
    // Double NextCycleCreated on same completed_cycle is rejected.
    let err = agg
        .decide(TaskRunCommand::CreateNextCycle {
            parent_cycle_id: CYCLE.parse().unwrap(),
            successor_cycle_id: CYCLE3.parse().unwrap(),
        })
        .unwrap_err();
    assert!(matches!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::SuccessorAlreadyAllocated
        }
    ));
}

// ── GATE-P5-005: plan_restores_exact_proposal_indexes ──────────────────

#[test]
fn plan_restores_exact_proposal_indexes() {
    let mut stream = evaluating_stream();
    // Override the PlanCommitted to carry indexes [0,1,2].
    stream[6] = envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0, 1, 2]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0, 1, 2],
        },
    );
    let agg = TaskRun::replay(&stream).unwrap();
    let active = agg.active_cycle().unwrap();
    assert_eq!(active.expected_proposal_indexes, vec![0, 1, 2]);
    assert_eq!(
        active
            .plan_revision_ref
            .as_ref()
            .unwrap()
            .expected_proposal_indexes,
        vec![0u32, 1, 2]
    );
}

// ── GATE-P5-006: outcome_requires_expected_unique_index ─────────────────

#[test]
fn outcome_requires_expected_unique_index() {
    let mut stream = evaluating_stream();
    // Plan with indexes [0,1].
    stream[6] = envelope(
        7,
        TaskRunEvent::PlanCommitted {
            cycle_id: CYCLE.parse().unwrap(),
            plan_revision_ref: plan_ref(vec![0, 1]),
            input_digest: digest(9),
            output_digest: digest(10),
            expected_proposal_indexes: vec![0, 1],
        },
    );
    // StepOutcomeRecorded with proposal_index=99 (not in plan).
    stream.push(envelope(
        8,
        TaskRunEvent::StepOutcomeRecorded {
            cycle_id: CYCLE.parse().unwrap(),
            outcome: StepOutcomeRecord {
                proposal_index: 99,
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
    let err = TaskRun::replay(&stream).unwrap_err();
    assert!(matches!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::ProposalIndexUnexpected
        }
    ));
}

// ── GATE-P5-008: wait_requires_current_wake_evidence ────────────────────

#[test]
fn wait_requires_current_wake_evidence() {
    let mut stream = evaluating_stream();
    stream.extend([
        envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Wait {
                    reason: "approval".into(),
                    wake_condition: WakeCondition {
                        kind: WakeConditionKind::Approval,
                        condition_ref: "approval:1".into(),
                        condition_digest: digest(11),
                    },
                },
            },
        ),
        // valid batch: LoopCycleCompleted(Wait) + WaitStarted
        envelope(9, TaskRunEvent::WaitStarted),
        // invalid batch: Resumed + LoopWakeAccepted with wrong condition_digest
        envelope(10, TaskRunEvent::Resumed),
        envelope(
            11,
            TaskRunEvent::LoopWakeAccepted {
                cycle_id: CYCLE.parse().unwrap(),
                wake_evidence_ref: WakeEvidenceRef {
                    cycle_id: CYCLE.parse().unwrap(),
                    condition_digest: digest(99),
                    source: WakeEvidenceSource::Approval,
                    evidence_id: OTHER.parse().unwrap(),
                    evidence_digest: digest(12),
                    observed_at_unix_us: 1000,
                    authority_revision: "approval-v1".into(),
                },
            },
        ),
    ]);
    let err = TaskRun::replay(&stream).unwrap_err();
    assert!(matches!(
        err,
        DomainError::LoopInvariantViolation {
            violation: LoopInvariantViolation::WakeEvidenceMismatch
        }
    ));
}

// ── GATE-P5-009: complete_and_fail_are_terminal ────────────────────────

#[test]
fn complete_and_fail_are_terminal() {
    // Complete → Succeeded.
    let mut complete_stream = evaluating_stream();
    complete_stream.extend([
        envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Complete {
                    plan_evaluation_ref: evaluation_ref(),
                },
            },
        ),
        envelope(
            9,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            },
        ),
    ]);
    let agg = TaskRun::replay(&complete_stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Succeeded);
    assert!(agg.state().is_terminal());

    // Fail → Failed.
    let mut fail_stream = evaluating_stream();
    fail_stream.extend([
        envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Fail {
                    reason: "failed".into(),
                    unresolved_proposals: vec![],
                },
            },
        ),
        envelope(
            9,
            TaskRunEvent::TaskRunFailed {
                reason: "failed".into(),
            },
        ),
    ]);
    let agg = TaskRun::replay(&fail_stream).unwrap();
    assert_eq!(agg.state(), TaskRunState::Failed);
    assert!(agg.state().is_terminal());

    // LoopCycleStarted on terminal state is rejected during replay.
    let mut terminal_then_cycle = evaluating_stream();
    terminal_then_cycle.extend([
        envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Complete {
                    plan_evaluation_ref: evaluation_ref(),
                },
            },
        ),
        envelope(
            9,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            },
        ),
        envelope(
            10,
            TaskRunEvent::LoopCycleStarted {
                cycle_id: SUCCESSOR.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                sequence: 1,
                parent_cycle_id: Some(CYCLE.parse().unwrap()),
            },
        ),
    ]);
    let err = TaskRun::replay(&terminal_then_cycle).unwrap_err();
    assert!(matches!(
        err,
        DomainError::InvalidTransition {
            from: TaskRunState::Succeeded,
            ..
        }
    ));
}

// ── GATE-P5-014: invalid_event_preserves_state ──────────────────────────
