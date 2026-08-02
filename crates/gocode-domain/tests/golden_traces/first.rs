
// ─── Golden trace 1: CreateTaskRun → TaskRunCreated → state=Created ───────

#[test]
fn golden_create_task_run() {
    let cmd = CreateTaskRun {
        taskrun_id: TR_ID.parse().unwrap(),
        conversation_id: CONV_ID.parse().unwrap(),
        workspace_id: WS_ID.parse().unwrap(),
    };

    let draft = TaskRun::decide_create(cmd).unwrap();

    // Expected: TaskRunCreated event
    assert_eq!(*draft.payload(), TaskRunEvent::TaskRunCreated);
    assert_eq!(draft.schema_version(), 1);

    // Expected aggregate ID
    let expected_agg_id: AggregateId = AggregateId::TaskRun(TR_ID.parse().unwrap());
    assert_eq!(*draft.aggregate_id(), expected_agg_id);
}

// ─── Golden trace 2: Created + TaskRunQueued → Queued ──────────────────────

#[test]
fn golden_created_to_queued() {
    let mut agg = created_aggregate();
    assert_eq!(agg.state(), TaskRunState::Created);

    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();

    // Expected: state is Queued
    assert_eq!(agg.state(), TaskRunState::Queued);
}

// ─── Golden trace 3: Queued + Admit → Admitted ─────────────────────────────

#[test]
fn golden_queued_to_admitted() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();

    let drafts = agg.decide(TaskRunCommand::Admit).unwrap();

    // Expected: single TaskRunAdmitted event
    assert_eq!(drafts.len(), 1);
    assert_eq!(*drafts[0].payload(), TaskRunEvent::TaskRunAdmitted);

    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    assert_eq!(agg.state(), TaskRunState::Admitted);
}

// ─── Golden trace 4: Admitted + AttemptStarted → Running ──────────────────

#[test]
fn golden_admitted_to_running() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();

    let aid: AttemptId = ATT_ID.parse().unwrap();
    let drafts = agg
        .decide(TaskRunCommand::StartAttempt { attempt_id: aid })
        .unwrap();

    // Expected: single AttemptStarted with correct attempt_id
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        *drafts[0].payload(),
        TaskRunEvent::AttemptStarted { attempt_id: aid }
    );

    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Running);
    assert_eq!(agg.active_attempt(), Some(&aid));
    assert_eq!(agg.attempt_history(), &[aid]);
}

// ─── Golden trace 5: Running + Complete(Success) → Succeeded ──────────────

#[test]
fn golden_running_to_succeeded() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid: AttemptId = ATT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();

    let drafts = agg
        .decide(TaskRunCommand::Complete {
            result: TerminalResult::Success,
        })
        .unwrap();

    // Expected: TaskRunCompleted with Success
    assert_eq!(
        *drafts[0].payload(),
        TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success
        }
    );

    agg.apply_payload(&TaskRunEvent::TaskRunCompleted {
        result: TerminalResult::Success,
    })
    .unwrap();
    assert_eq!(agg.state(), TaskRunState::Succeeded);
    assert!(agg.state().is_terminal());
    assert_eq!(agg.terminal_result(), Some(&TerminalResult::Success));
    assert!(agg.active_attempt().is_none());
}

// ─── Golden trace 6: Cancellation path ────────────────────────────────────

#[test]
fn golden_cancellation_request_then_complete() {
    let mut agg = created_aggregate();
    agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
    agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
    let aid: AttemptId = ATT_ID.parse().unwrap();
    agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
        .unwrap();

    // Step 1: request cancellation
    let drafts = agg.decide(TaskRunCommand::RequestCancellation).unwrap();
    assert_eq!(*drafts[0].payload(), TaskRunEvent::CancellationRequested);

    agg.apply_payload(&TaskRunEvent::CancellationRequested)
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Cancelling);

    // Step 2: complete cancellation
    let drafts = agg.decide(TaskRunCommand::CompleteCancellation).unwrap();
    assert_eq!(*drafts[0].payload(), TaskRunEvent::CancellationCompleted);

    agg.apply_payload(&TaskRunEvent::CancellationCompleted)
        .unwrap();
    assert_eq!(agg.state(), TaskRunState::Cancelled);
    assert!(agg.active_attempt().is_none());
}

// ─── Golden trace 7: Invalid transition → DomainError ─────────────────────

#[test]
fn golden_invalid_transition_created_to_attempt_started() {
    let agg = created_aggregate();
    let aid: AttemptId = ATT_ID.parse().unwrap();

    let err = agg
        .decide(TaskRunCommand::StartAttempt { attempt_id: aid })
        .unwrap_err();

    // Expected: InvalidTransition from Created with AttemptStarted kind
    assert!(matches!(
        err,
        gocode_domain::error::DomainError::InvalidTransition { .. }
    ));
}
