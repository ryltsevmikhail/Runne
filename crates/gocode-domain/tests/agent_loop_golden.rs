use gocode_domain::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
    WakeCondition, WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource,
};
use gocode_domain::command::{TaskRunCommand, TerminalResult};
use gocode_domain::context::ContextManifestRef;
use gocode_domain::error::{DomainError, LoopInvariantViolation};
use gocode_domain::event::{
    Actor, CommandContext, DomainEventDraft, EventEnvelope, Sensitivity, materialize_batch,
};
use gocode_domain::id::*;
use gocode_domain::plan::PlanRevisionRef;
use gocode_domain::recovery::{ReconciliationResultRef, ReconciliationStatus};
use gocode_domain::reference::{BudgetReservationRef, CheckpointRef, ResultRef};
use gocode_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use gocode_domain::timestamp::Timestamp;
use gocode_domain::verification::{PlanEvaluationRef, PlanEvaluationResult};

const TASK: &str = "018f2e3a-7000-7000-8000-000000000001";
const ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000002";
const CYCLE: &str = "018f2e3a-7000-7000-8000-000000000003";
const OTHER: &str = "018f2e3a-7000-7000-8000-000000000004";
const SUCCESSOR: &str = "018f2e3a-7000-7000-8000-000000000005";
const CYCLE3: &str = "018f2e3a-7000-7000-8000-000000000006";

fn digest(byte: u8) -> IntegrityDigest {
    IntegrityDigest::from_bytes([byte; 32])
}

fn context_ref() -> ContextManifestRef {
    ContextManifestRef {
        manifest_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        cycle_id: CYCLE.parse().unwrap(),
        revision: 1,
        policy_revision: "context-v1".into(),
        integrity_digest: digest(1),
    }
}

fn budget_ref() -> BudgetReservationRef {
    BudgetReservationRef {
        reservation_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        attempt_id: ATTEMPT.parse().unwrap(),
        retry_ordinal: 1,
        reservation_digest: digest(2),
    }
}

fn plan_ref(indexes: Vec<u32>) -> PlanRevisionRef {
    PlanRevisionRef {
        plan_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        cycle_id: CYCLE.parse().unwrap(),
        revision: 1,
        context_manifest_ref: context_ref(),
        expected_proposal_indexes: indexes,
        proposal_batch_digest: digest(3),
        planning_policy_ref: ResultRef::new(OTHER.parse().unwrap(), "application/json", digest(4))
            .unwrap(),
        planning_budget_ref: budget_ref(),
        parent_ref: None,
        integrity_digest: digest(5),
    }
}

fn evaluation_ref() -> PlanEvaluationRef {
    PlanEvaluationRef {
        evaluation_id: OTHER.parse().unwrap(),
        taskrun_id: TASK.parse().unwrap(),
        plan_id: OTHER.parse().unwrap(),
        plan_revision: 1,
        evaluated_stream_head: 7,
        result: PlanEvaluationResult::Passed,
        gate_definitions_digest: digest(6),
        evidence_set_digest: digest(7),
        evaluation_digest: digest(8),
    }
}

fn envelope(sequence: u64, payload: TaskRunEvent) -> EventEnvelope<TaskRunEvent> {
    let taskrun_id: TaskRunId = TASK.parse().unwrap();
    let aggregate_id = AggregateId::TaskRun(taskrun_id);
    let draft = DomainEventDraft::new(
        aggregate_id.clone(),
        aggregate_id,
        1,
        Sensitivity::Sensitive,
        payload,
    );
    let command = CommandContext {
        command_id: TASK.parse().unwrap(),
        idempotency_key: IdempotencyKey::new("phase5-golden").unwrap(),
        actor: Actor::new("phase5-test").unwrap(),
    };
    let event_id: EventId = OTHER.parse().unwrap();
    materialize_batch(vec![draft], &[event_id], None, &command)
        .unwrap()
        .remove(0)
        .into_envelope(
            sequence,
            Timestamp::from_unix_micros(sequence as i64),
            digest(0),
        )
}

fn evaluating_stream() -> Vec<EventEnvelope<TaskRunEvent>> {
    vec![
        envelope(1, TaskRunEvent::TaskRunCreated),
        envelope(2, TaskRunEvent::TaskRunQueued),
        envelope(3, TaskRunEvent::TaskRunAdmitted),
        envelope(
            4,
            TaskRunEvent::AttemptStarted {
                attempt_id: ATTEMPT.parse().unwrap(),
            },
        ),
        envelope(
            5,
            TaskRunEvent::LoopCycleStarted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                sequence: 0,
                parent_cycle_id: None,
            },
        ),
        envelope(
            6,
            TaskRunEvent::ContextCommitted {
                cycle_id: CYCLE.parse().unwrap(),
                manifest_ref: context_ref(),
            },
        ),
        envelope(
            7,
            TaskRunEvent::PlanCommitted {
                cycle_id: CYCLE.parse().unwrap(),
                plan_revision_ref: plan_ref(vec![]),
                input_digest: digest(9),
                output_digest: digest(10),
                expected_proposal_indexes: vec![],
            },
        ),
    ]
}

#[test]
fn all_disposition_batches_replay_to_exact_final_state() {
    let cases = [
        (LoopDisposition::Continue, None, TaskRunState::Running),
        (
            LoopDisposition::Wait {
                reason: "approval".into(),
                wake_condition: WakeCondition {
                    kind: WakeConditionKind::Approval,
                    condition_ref: "approval:1".into(),
                    condition_digest: digest(11),
                },
            },
            Some(TaskRunEvent::WaitStarted),
            TaskRunState::Waiting,
        ),
        (
            LoopDisposition::Complete {
                plan_evaluation_ref: evaluation_ref(),
            },
            Some(TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            }),
            TaskRunState::Succeeded,
        ),
        (
            LoopDisposition::Fail {
                reason: "failed".into(),
                unresolved_proposals: vec![],
            },
            Some(TaskRunEvent::TaskRunFailed {
                reason: "failed".into(),
            }),
            TaskRunState::Failed,
        ),
    ];

    for (disposition, terminal_event, expected_state) in cases {
        let mut stream = evaluating_stream();
        stream.push(envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition,
            },
        ));
        if let Some(event) = terminal_event {
            stream.push(envelope(9, event));
        }
        assert_eq!(TaskRun::replay(&stream).unwrap().state(), expected_state);
    }
}

#[test]
fn torn_disposition_batch_is_rejected_before_success() {
    let mut stream = evaluating_stream();
    stream.push(envelope(
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
    ));
    assert_eq!(
        TaskRun::replay(&stream).unwrap_err(),
        DomainError::CorruptCommandBatch
    );
}

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
