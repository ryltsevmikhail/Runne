#[test]
fn closed_snapshot_round_trips_running_task_run() {
    let aggregate = running_aggregate();

    let encoded = aggregate.snapshot_v1().encode().unwrap();
    let decoded = TaskRunSnapshotV1::decode(&encoded).unwrap();
    assert_eq!(decoded, aggregate.snapshot_v1());
}

#[test]
fn closed_snapshot_decodes_legacy_v1_and_rejects_invalid_input_marker() {
    let aggregate = create_aggregate();
    let legacy = aggregate.snapshot_v1().encode().unwrap();
    assert_eq!(legacy[0], 1);
    assert_eq!(TaskRunSnapshotV1::decode(&legacy).unwrap(), aggregate.snapshot_v1());

    let mut submitted = aggregate;
    submitted.apply_payload(&TaskRunEvent::TaskRunSubmitted {
        conversation_id: CONVERSATION_ID.parse().unwrap(),
        workspace_id: WORKSPACE_ID.parse().unwrap(),
        input: TaskRunInput::new("prompt".to_owned()).unwrap(),
    }).unwrap();
    let mut invalid_marker = submitted.snapshot_v1().encode().unwrap();
    let marker_index = invalid_marker.len() - 16 - 16 - 4 - "prompt".len() - 1;
    invalid_marker[marker_index] = 2;
    assert_eq!(TaskRunSnapshotV1::decode(&invalid_marker), Err(TaskRunSnapshotError::InvalidEncoding));
}

#[test]
fn closed_snapshot_rejects_truncation_unknown_version_trailing_and_oversize() {
    let bytes = running_aggregate().snapshot_v1().encode().unwrap();
    let malformed = [
        bytes[..bytes.len() - 1].to_vec(),
        {
            let mut value = bytes.clone();
            value[0] = 9;
            value
        },
        {
            let mut value = bytes.clone();
            value.push(0);
            value
        },
        vec![0; 512 * 1024 + 1],
    ];

    for bytes in malformed {
        assert_eq!(
            TaskRunSnapshotV1::decode(&bytes),
            Err(TaskRunSnapshotError::InvalidEncoding)
        );
    }
}

#[test]
fn closed_snapshot_preserves_every_terminal_result_and_lifecycle_tag() {
    let taskrun_id: TaskRunId = VALID_UUID.parse().unwrap();
    let attempt_id: AttemptId = ATTEMPT_ID.parse().unwrap();
    let states = [
        TaskRunState::Created,
        TaskRunState::Queued,
        TaskRunState::Admitted,
        TaskRunState::Running,
        TaskRunState::Waiting,
        TaskRunState::Retrying,
        TaskRunState::Checkpointing,
        TaskRunState::Cancelling,
        TaskRunState::Reconciling,
        TaskRunState::Succeeded,
        TaskRunState::Failed,
        TaskRunState::Cancelled,
        TaskRunState::BudgetExhausted,
        TaskRunState::PolicyDenied,
        TaskRunState::Unrecoverable,
    ];
    for state in states {
        let requires_attempt = !matches!(
            state,
            TaskRunState::Created
                | TaskRunState::Queued
                | TaskRunState::Admitted
                | TaskRunState::Cancelled
        );
        let terminal = if state == TaskRunState::Succeeded {
            Some(TerminalResult::Failure {
                reason: "terminal".into(),
            })
        } else {
            None
        };
        let aggregate = TaskRun {
            id: taskrun_id,
            conversation_id: None,
            workspace_id: None,
            input: None,
            state,
            active_attempt: (requires_attempt && !state.is_terminal()).then_some(attempt_id),
            attempt_history: requires_attempt.then_some(attempt_id).into_iter().collect(),
            terminal_result: terminal,
            active_cycle: None,
            last_completed_cycle: None,
            pending_successor: None,
            pending_loop_wait: None,
            pending_retry: None,
            pending_loop_checkpoint: None,
            cycle_history: vec![],
            recovery_generation: 0,
        };
        let encoded = aggregate.snapshot_v1().encode().unwrap();
        let decoded = TaskRunSnapshotV1::decode(&encoded)
            .unwrap_or_else(|error| panic!("{state:?}: {error:?}"));
        assert_eq!(decoded, aggregate.snapshot_v1());
    }
}

#[test]
fn closed_snapshot_round_trips_every_real_lifecycle_prefix() {
    let created = create_aggregate();
    let mut queued = created.clone();
    queued.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    let mut admitted = queued.clone();
    admitted
        .apply_payload(&TaskRunEvent::TaskRunAdmitted)
        .unwrap();
    let running = running_aggregate();

    let mut waiting = running.clone();
    waiting.apply_payload(&TaskRunEvent::WaitStarted).unwrap();
    let mut retrying = running.clone();
    retrying
        .apply_payload(&TaskRunEvent::RetryStarted {
            attempt_id: ATTEMPT_ID2.parse().unwrap(),
        })
        .unwrap();
    let mut checkpointing = running.clone();
    checkpointing
        .apply_payload(&TaskRunEvent::CheckpointStarted)
        .unwrap();
    let mut cancelling = running.clone();
    cancelling
        .apply_payload(&TaskRunEvent::CancellationRequested)
        .unwrap();
    let mut reconciling = running.clone();
    reconciling
        .apply_payload(&TaskRunEvent::ReconciliationStarted)
        .unwrap();
    let mut succeeded = running.clone();
    succeeded
        .apply_payload(&TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        })
        .unwrap();
    let mut failed = running.clone();
    failed
        .apply_payload(&TaskRunEvent::TaskRunFailed {
            reason: "failed".into(),
        })
        .unwrap();
    let mut budget_exhausted = running.clone();
    budget_exhausted
        .apply_payload(&TaskRunEvent::BudgetExhausted)
        .unwrap();
    let mut policy_denied = running.clone();
    policy_denied
        .apply_payload(&TaskRunEvent::PolicyDenied)
        .unwrap();
    let mut unrecoverable = reconciling.clone();
    unrecoverable
        .apply_payload(&TaskRunEvent::Unrecoverable)
        .unwrap();
    let mut cancelled = queued.clone();
    cancelled
        .apply_payload(&TaskRunEvent::TaskRunCancelled)
        .unwrap();

    for aggregate in [
        created,
        queued,
        admitted,
        running,
        waiting,
        retrying,
        checkpointing,
        cancelling,
        reconciling,
        succeeded,
        failed,
        cancelled,
        budget_exhausted,
        policy_denied,
        unrecoverable,
    ] {
        assert_snapshot_round_trip(aggregate);
    }
}

#[test]
fn closed_snapshot_rejects_duplicate_attempt_and_terminal_state_mismatches() {
    let mut duplicate = running_aggregate();
    duplicate
        .attempt_history
        .push(*duplicate.active_attempt().unwrap());
    assert_eq!(
        duplicate.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut terminal = running_aggregate();
    terminal.state = TaskRunState::Succeeded;
    assert_eq!(
        terminal.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );

    let mut retry = running_aggregate();
    retry.state = TaskRunState::Retrying;
    assert!(retry.snapshot_v1().encode().is_ok());
}

#[test]
fn closed_snapshot_rejects_incomplete_checkpoint_even_after_cancellation() {
    let mut aggregate = running_aggregate();
    aggregate.state = TaskRunState::Cancelling;
    aggregate.pending_loop_checkpoint = Some(PendingLoopCheckpoint {
        checkpoint_id: WORKSPACE_ID.parse().unwrap(),
        start_position: 9,
        expected_integrity_digest: IntegrityDigest::from_bytes([7; 32]),
        recorded_integrity_digest: None,
    });

    assert_eq!(
        aggregate.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidState)
    );
}

#[test]
fn closed_snapshot_rejects_unknown_nested_terminal_tag() {
    let taskrun_id: TaskRunId = VALID_UUID.parse().unwrap();
    let attempt_id: AttemptId = ATTEMPT_ID.parse().unwrap();
    let aggregate = TaskRun {
        id: taskrun_id,
        conversation_id: None,
        workspace_id: None,
        input: None,
        state: TaskRunState::Succeeded,
        active_attempt: None,
        attempt_history: vec![attempt_id],
        terminal_result: Some(TerminalResult::Success),
        active_cycle: None,
        last_completed_cycle: None,
        pending_successor: None,
        pending_loop_wait: None,
        pending_retry: None,
        pending_loop_checkpoint: None,
        cycle_history: vec![],
        recovery_generation: 0,
    };
    let mut bytes = aggregate.snapshot_v1().encode().unwrap();
    bytes[39] = 9;

    assert_eq!(
        TaskRunSnapshotV1::decode(&bytes),
        Err(TaskRunSnapshotError::InvalidEncoding)
    );
}

#[test]
fn closed_snapshot_encode_rejects_non_uuid_v7_identifier() {
    let mut aggregate = running_aggregate();
    aggregate.id = TaskRunId::from_bytes([0; 16]);

    assert_eq!(
        aggregate.snapshot_v1().encode(),
        Err(TaskRunSnapshotError::InvalidEncoding)
    );
}

include!("snapshot_fixtures.rs");
include!("snapshot_matrix.rs");
include!("snapshot_negatives.rs");
