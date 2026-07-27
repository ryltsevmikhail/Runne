use gocode_domain::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
    WakeCondition, WakeConditionKind,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::context::ContextManifestRef;
use gocode_domain::error::DomainError;
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
