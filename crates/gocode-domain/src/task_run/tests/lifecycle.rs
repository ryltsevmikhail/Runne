    // ─── Creation ──────────────────────────────────────────────────────────

    #[test]
    fn test_decide_create_produces_draft() {
        let cmd = make_create();
        let draft = TaskRun::decide_create(cmd).unwrap();
        assert_eq!(*draft.payload(), TaskRunEvent::TaskRunCreated);
        assert_eq!(draft.schema_version(), 1);
    }

    #[test]
    fn decide_create_running_emits_the_exact_valid_lifecycle_prefix() {
        let events = TaskRun::decide_create_running(
            make_create(),
            ATTEMPT_ID.parse().expect("valid attempt ID"),
        )
        .unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.payload().kind())
                .collect::<Vec<_>>(),
            vec![
                TaskRunEventKind::TaskRunCreated,
                TaskRunEventKind::TaskRunQueued,
                TaskRunEventKind::TaskRunAdmitted,
                TaskRunEventKind::AttemptStarted,
            ]
        );
        assert!(
            events
                .iter()
                .all(|event| event.sensitivity() == &Sensitivity::Public)
        );
    }

    #[test]
    fn test_replay_created() {
        let events = &[make_envelope(
            1,
            TaskRunEvent::TaskRunCreated,
            VALID_UUID.parse().unwrap(),
        )];
        let agg = TaskRun::replay(events).unwrap();
        assert_eq!(agg.state(), TaskRunState::Created);
    }

    // ─── Full lifecycle ───────────────────────────────────────────────────

    #[test]
    fn test_full_lifecycle_created_to_succeeded() {
        let mut agg = create_aggregate();
        assert_eq!(agg.state(), TaskRunState::Created);

        // created → queued
        let _drafts = agg
            .decide(TaskRunCommand::Admit)
            .map_err(|e| format!("{:?}", e))
            .unwrap_err();
        // Wait: Admit is not valid from Created — need TaskRunQueued event first
        // Actually per transition table: created + TaskRunQueued → queued
        // But there's no TaskRunQueued command — it's an internal event.
        // Let me use the apply path directly:
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        assert_eq!(agg.state(), TaskRunState::Queued);

        // queued → admitted via command
        let drafts = agg.decide(TaskRunCommand::Admit).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::TaskRunAdmitted);
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Admitted);

        // admitted → running via StartAttempt
        let attempt_id: AttemptId = ATTEMPT_ID.parse().unwrap();
        let drafts = agg
            .decide(TaskRunCommand::StartAttempt { attempt_id })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::AttemptStarted { .. }
        ));
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id })
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
        assert_eq!(agg.active_attempt(), Some(&attempt_id));

        // running → succeeded
        let drafts = agg
            .decide(TaskRunCommand::Complete {
                result: TerminalResult::Success,
            })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::TaskRunCompleted { .. }
        ));
        agg.apply_payload(&TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        })
        .unwrap();
        assert_eq!(agg.state(), TaskRunState::Succeeded);
        assert!(agg.state().is_terminal());
    }

    // ─── Waiting/resume cycle ─────────────────────────────────────────────

    #[test]
    fn test_waiting_cycle() {
        let mut agg = create_aggregate();
        // created → queued → admitted → running
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);

        // running → waiting
        let drafts = agg.decide(TaskRunCommand::WaitForApproval).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::WaitStarted);
        agg.apply_payload(&TaskRunEvent::WaitStarted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Waiting);

        // waiting → running
        let drafts = agg.decide(TaskRunCommand::Resume).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::Resumed);
        agg.apply_payload(&TaskRunEvent::Resumed).unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Retry cycle ──────────────────────────────────────────────────────

    #[test]
    fn test_retry_cycle() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // running → retrying
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

        // retrying → running
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

    // ─── Checkpoint cycle ─────────────────────────────────────────────────

    #[test]
    fn test_checkpoint_cycle() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // running → checkpointing
        let drafts = agg.decide(TaskRunCommand::StartCheckpoint).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CheckpointStarted);
        agg.apply_payload(&TaskRunEvent::CheckpointStarted).unwrap();
        assert_eq!(agg.state(), TaskRunState::Checkpointing);

        // checkpointing → running
        let drafts = agg.decide(TaskRunCommand::CommitCheckpoint).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CheckpointCommitted);
        agg.apply_payload(&TaskRunEvent::CheckpointCommitted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }

    // ─── Cancellation cycle ───────────────────────────────────────────────

    #[test]
    fn test_cancellation_cycle_from_running() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // running → cancelling
        let drafts = agg.decide(TaskRunCommand::RequestCancellation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CancellationRequested);
        agg.apply_payload(&TaskRunEvent::CancellationRequested)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelling);

        // cancelling → cancelled
        let drafts = agg.decide(TaskRunCommand::CompleteCancellation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::CancellationCompleted);
        agg.apply_payload(&TaskRunEvent::CancellationCompleted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelled);
        assert!(agg.state().is_terminal());
        assert!(agg.active_attempt().is_none());
    }

    // ─── Failed ───────────────────────────────────────────────────────────

    #[test]
    fn test_failure_path() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        let drafts = agg
            .decide(TaskRunCommand::Fail {
                reason: "test failure".into(),
            })
            .unwrap();
        assert!(matches!(
            drafts[0].payload(),
            TaskRunEvent::TaskRunFailed { .. }
        ));
        agg.apply_payload(&TaskRunEvent::TaskRunFailed {
            reason: "test failure".into(),
        })
        .unwrap();
        assert_eq!(agg.state(), TaskRunState::Failed);
        assert!(agg.state().is_terminal());
        assert!(agg.active_attempt().is_none());
    }

    #[test]
    fn provider_output_rejection_uses_closed_terminal_code() {
        let agg = running_aggregate();

        let drafts = agg
            .decide(TaskRunCommand::FailGeneration {
                reason: crate::conversation::GenerationFailureReason::ProviderOutputRejected,
            })
            .unwrap();

        assert_eq!(
            drafts[0].payload(),
            &TaskRunEvent::TaskRunFailed {
                reason: "provider_output_rejected".into(),
            }
        );
    }

    // ─── Reconciliation ───────────────────────────────────────────────────

    #[test]
    fn test_reconciliation_to_running() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        let drafts = agg.decide(TaskRunCommand::StartReconciliation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::ReconciliationStarted);
        agg.apply_payload(&TaskRunEvent::ReconciliationStarted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Reconciling);

        let drafts = agg.decide(TaskRunCommand::CompleteReconciliation).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::Reconciled);
        agg.apply_payload(&TaskRunEvent::Reconciled).unwrap();
        assert_eq!(agg.state(), TaskRunState::Running);
    }
