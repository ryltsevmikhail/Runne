// ─── Retry cycle ──────────────────────────────────────────────────────

#[test]
fn test_retry_cycle() {
    let mut agg = create_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();

    let aid2: AttemptId = ATTEMPT_ID2.parse().unwrap();
    let drafts = agg
        .decide(TaskRunCommand::StartRetry { attempt_id: aid2 })
        .unwrap();
    assert!(matches!(
        drafts[0].payload(),
        TaskRunEvent::RetryStarted { .. }
    ));
    agg.apply_payload(&TaskRunEvent::RetryStarted { attempt_id: aid2 })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Retrying);
    assert_eq!(agg.active_attempt(), Some(&aid2));

    let drafts = agg
        .decide(TaskRunCommand::CompleteRetry { attempt_id: aid2 })
        .unwrap();
    assert_eq!(
        drafts[0].payload(),
        &TaskRunEvent::RetryCompleted { attempt_id: aid2 }
    );
    agg.apply_payload(&TaskRunEvent::RetryCompleted { attempt_id: aid2 })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
}

#[test]
fn retry_completion_requires_the_current_retry_attempt() {
    let mut aggregate = running_aggregate();
    let first_attempt: AttemptId = ATTEMPT_ID.parse().unwrap();
    let retry_attempt: AttemptId = ATTEMPT_ID2.parse().unwrap();
    let unrelated_attempt: AttemptId = WORKSPACE_ID.parse().unwrap();
    aggregate
        .apply_payload(&TaskRunEvent::RetryStarted {
            attempt_id: retry_attempt,
        })
        .unwrap();

    for wrong_attempt in [first_attempt, unrelated_attempt] {
        assert!(matches!(
            aggregate.decide(TaskRunCommand::CompleteRetry {
                attempt_id: wrong_attempt,
            }),
            Err(DomainError::LoopInvariantViolation {
                violation: LoopInvariantViolation::MissingActiveAttempt
            })
        ));
        assert_eq!(
            aggregate.apply_payload(&TaskRunEvent::RetryCompleted {
                attempt_id: wrong_attempt,
            }),
            Err(TaskRun::loop_error(LoopInvariantViolation::MissingActiveAttempt))
        );
        assert_eq!(aggregate.state(), TaskRunState::Retrying);
    }

    let completion = aggregate
        .decide(TaskRunCommand::CompleteRetry {
            attempt_id: retry_attempt,
        })
        .unwrap();
    assert_eq!(
        completion[0].payload(),
        &TaskRunEvent::RetryCompleted {
            attempt_id: retry_attempt
        }
    );
    aggregate
        .apply_payload(&TaskRunEvent::RetryCompleted {
            attempt_id: retry_attempt,
        })
        .unwrap();
    assert_eq!(aggregate.state(), TaskRunState::Running);
    let snapshot = TaskRunSnapshotV1::decode(&aggregate.snapshot_v1().encode().unwrap()).unwrap();
    assert_eq!(snapshot, aggregate.snapshot_v1());
}

#[test]
fn replay_rejects_retry_completion_for_any_noncurrent_attempt() {
    let taskrun_id: TaskRunId = VALID_UUID.parse().unwrap();
    let first_attempt: AttemptId = ATTEMPT_ID.parse().unwrap();
    let retry_attempt: AttemptId = ATTEMPT_ID2.parse().unwrap();
    let stream = [
        make_envelope(1, TaskRunEvent::TaskRunCreated, taskrun_id),
        make_envelope(2, TaskRunEvent::TaskRunQueued, taskrun_id),
        make_envelope(3, TaskRunEvent::TaskRunAdmitted, taskrun_id),
        make_envelope(
            4,
            TaskRunEvent::AttemptStarted {
                attempt_id: first_attempt,
            },
            taskrun_id,
        ),
        make_envelope(
            5,
            TaskRunEvent::RetryStarted {
                attempt_id: retry_attempt,
            },
            taskrun_id,
        ),
        make_envelope(
            6,
            TaskRunEvent::RetryCompleted {
                attempt_id: first_attempt,
            },
            taskrun_id,
        ),
    ];

    assert_eq!(
        TaskRun::replay(&stream),
        Err(TaskRun::loop_error(LoopInvariantViolation::MissingActiveAttempt))
    );
}
