    #[test]
    fn test_reconciliation_to_unrecoverable() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        agg.apply_payload(&TaskRunEvent::ReconciliationStarted)
            .unwrap();
        assert_eq!(agg.state(), TaskRunState::Reconciling);

        let drafts = agg.decide(TaskRunCommand::MarkUnrecoverable).unwrap();
        assert_eq!(drafts[0].payload(), &TaskRunEvent::Unrecoverable);
        agg.apply_payload(&TaskRunEvent::Unrecoverable).unwrap();
        assert_eq!(agg.state(), TaskRunState::Unrecoverable);
        assert!(agg.state().is_terminal());
    }

    #[test]
    fn explicit_unknown_successor_is_terminal_from_running_and_rejects_queued() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        let successor: TaskRunId = "018f0000-0000-7000-8000-000000000002".parse().unwrap();
        let digest = IntegrityDigest::from_bytes([0x5a; 32]);
        let drafts = agg
            .decide(TaskRunCommand::UserSupersedeUnknown {
                predecessor_attempt_id: aid,
                successor_taskrun_id: successor,
                acknowledgement_digest: digest,
            })
            .unwrap();
        assert_eq!(
            drafts[0].payload(),
            &TaskRunEvent::UserSupersedeUnknown {
                predecessor_attempt_id: aid,
                successor_taskrun_id: successor,
                acknowledgement_digest: digest,
            }
        );
        agg.apply_payload(drafts[0].payload()).unwrap();
        assert_eq!(agg.state(), TaskRunState::Unrecoverable);
        assert!(agg.active_attempt().is_none());

        let queued = create_aggregate();
        assert!(matches!(
            queued.decide(TaskRunCommand::UserSupersedeUnknown {
                predecessor_attempt_id: aid,
                successor_taskrun_id: successor,
                acknowledgement_digest: digest,
            }),
            Err(DomainError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn unknown_successor_replay_requires_the_exact_active_attempt() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        let wrong: AttemptId = "018f0000-0000-7000-8000-000000000099".parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        let event = TaskRunEvent::UserSupersedeUnknown {
            predecessor_attempt_id: wrong,
            successor_taskrun_id: "018f0000-0000-7000-8000-000000000002"
                .parse()
                .unwrap(),
            acknowledgement_digest: IntegrityDigest::from_bytes([0x5a; 32]),
        };
        assert!(agg.apply_payload(&event).is_err());
        assert_eq!(agg.state(), TaskRunState::Running);
        assert_eq!(agg.active_attempt(), Some(&aid));
    }

    // ─── Direct cancel from non-running states ────────────────────────────

    #[test]
    fn test_direct_cancel_from_queued() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        // direct cancel from queued (no CancellationRequested needed for direct path)
        agg.apply_payload(&TaskRunEvent::TaskRunCancelled).unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelled);
    }

    #[test]
    fn test_direct_cancel_from_admitted() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunCancelled).unwrap();
        assert_eq!(agg.state(), TaskRunState::Cancelled);
    }

    // ─── Replay round-trip ────────────────────────────────────────────────

    #[test]
    fn test_replay_roundtrip_created_to_succeeded() {
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunQueued, tr_id),
            make_envelope(3, TaskRunEvent::TaskRunAdmitted, tr_id),
            make_envelope(4, TaskRunEvent::AttemptStarted { attempt_id: aid }, tr_id),
            make_envelope(
                5,
                TaskRunEvent::TaskRunCompleted {
                    result: TerminalResult::Success,
                },
                tr_id,
            ),
        ];
        let agg = TaskRun::replay(events).unwrap();
        assert_eq!(agg.state(), TaskRunState::Succeeded);
        assert_eq!(*agg.id(), tr_id);
        assert_eq!(agg.attempt_history(), &[aid]);
    }

    // ─── L0 tests: invalid transitions ────────────────────────────────────

    #[test]
    fn test_invalid_terminal_immutable() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunCompleted {
            result: TerminalResult::Success,
        })
        .unwrap();
        assert!(agg.state().is_terminal());

        // Any command on terminal state → TerminalImmutable
        let err = agg.decide(TaskRunCommand::Admit).unwrap_err();
        assert!(matches!(err, DomainError::TerminalImmutable { .. }));
    }

    #[test]
    fn test_invalid_transition_wrong_state() {
        let agg = create_aggregate();
        // Created → Admit is not valid (need Queued first)
        let err = agg.decide(TaskRunCommand::Admit).unwrap_err();
        assert!(matches!(err, DomainError::InvalidTransition { .. }));
    }

    #[test]
    fn test_duplicate_attempt_id() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        agg.apply_payload(&TaskRunEvent::TaskRunAdmitted).unwrap();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid })
            .unwrap();

        // Try to start retry with same attempt ID
        let err = agg
            .decide(TaskRunCommand::StartRetry { attempt_id: aid })
            .unwrap_err();
        assert!(matches!(err, DomainError::DuplicateAttemptId { .. }));
    }

    #[test]
    fn test_replay_empty_events() {
        let events: &[EventEnvelope<TaskRunEvent>] = &[];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::MissingCreationEvent { .. }));
    }

    #[test]
    fn test_replay_missing_creation_event() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[make_envelope(1, TaskRunEvent::TaskRunQueued, tr_id)];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::MissingCreationEvent { .. }));
    }

    #[test]
    fn test_replay_sequence_gap() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(3, TaskRunEvent::TaskRunQueued, tr_id), // gap: expected 2
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::SequenceGap { .. }));
    }

    #[test]
    fn test_replay_invalid_initial_sequence() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[make_envelope(5, TaskRunEvent::TaskRunCreated, tr_id)];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::InvalidInitialSequence { .. }));
    }

    #[test]
    fn test_replay_duplicate_creation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunCreated, tr_id),
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::DuplicateCreationEvent { .. }));
    }

    #[test]
    fn test_replay_aggregate_id_mismatch_by_taskrun_id() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let tr_id2: TaskRunId = ATTEMPT_ID.parse().unwrap();
        let events = &[
            make_envelope(1, TaskRunEvent::TaskRunCreated, tr_id),
            make_envelope(2, TaskRunEvent::TaskRunQueued, tr_id2),
        ];
        let err = TaskRun::replay(events).unwrap_err();
        assert!(matches!(err, DomainError::AggregateIdMismatch { .. }));
    }

    #[test]
    fn test_apply_rejects_non_taskrun_correlation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let mut aggregate = create_aggregate();
        let event = make_envelope_with_correlation(
            2,
            TaskRunEvent::TaskRunQueued,
            tr_id,
            AggregateId::Workspace(WORKSPACE_ID.parse().unwrap()),
        );

        let err = aggregate.apply(&event).unwrap_err();
        assert_eq!(
            err,
            DomainError::AggregateIdMismatch {
                expected: AggregateId::TaskRun(tr_id),
                actual: AggregateId::Workspace(WORKSPACE_ID.parse().unwrap()),
            }
        );
    }

    #[test]
    fn test_replay_rejects_non_taskrun_correlation() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let event = make_envelope_with_correlation(
            1,
            TaskRunEvent::TaskRunCreated,
            tr_id,
            AggregateId::Conversation(CONVERSATION_ID.parse().unwrap()),
        );

        let err = TaskRun::replay(&[event]).unwrap_err();
        assert_eq!(
            err,
            DomainError::AggregateIdMismatch {
                expected: AggregateId::TaskRun(tr_id),
                actual: AggregateId::Conversation(CONVERSATION_ID.parse().unwrap()),
            }
        );
    }
