    #[test]
    fn phase5_event_kinds_are_exactly_thirteen() {
        let kinds = [
            TaskRunEventKind::LoopCycleStarted,
            TaskRunEventKind::ContextCommitted,
            TaskRunEventKind::PlanCommitted,
            TaskRunEventKind::StepOutcomeRecorded,
            TaskRunEventKind::LoopCycleCompleted,
            TaskRunEventKind::NextCycleCreated,
            TaskRunEventKind::RetryScheduled,
            TaskRunEventKind::ActivateScheduledRetryAttempt,
            TaskRunEventKind::RecoveryResumeStarted,
            TaskRunEventKind::LoopCheckpointStarted,
            TaskRunEventKind::LoopCheckpointRecorded,
            TaskRunEventKind::LoopCheckpointCommitted,
            TaskRunEventKind::LoopWakeAccepted,
        ];

        assert_eq!(kinds.len(), 13);
    }

    #[test]
    fn initial_cycle_is_attempt_bound_unique_and_failure_preserves_state() {
        let mut aggregate = running_aggregate();
        let cycle_id: CycleId = WORKSPACE_ID.parse().unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::LoopCycleStarted {
                cycle_id,
                attempt_id: ATTEMPT_ID.parse().unwrap(),
                sequence: 0,
                parent_cycle_id: None,
            })
            .unwrap();
        let before = aggregate.clone();

        let error = aggregate
            .apply_payload(&TaskRunEvent::LoopCycleStarted {
                cycle_id: CONVERSATION_ID.parse().unwrap(),
                attempt_id: ATTEMPT_ID.parse().unwrap(),
                sequence: 0,
                parent_cycle_id: None,
            })
            .unwrap_err();

        assert_eq!(
            error,
            DomainError::LoopInvariantViolation {
                violation: LoopInvariantViolation::ActiveCycleExists,
            }
        );
        assert_eq!(aggregate, before);
        assert_eq!(aggregate.cycle_history().len(), 1);
    }

    #[test]
    fn checkpoint_commit_requires_exact_record_and_preserves_state_on_error() {
        let mut aggregate = running_aggregate();
        let checkpoint_id: CheckpointId = WORKSPACE_ID.parse().unwrap();
        aggregate
            .apply_payload(&TaskRunEvent::LoopCheckpointStarted {
                checkpoint_id,
                event_position: 5,
                integrity_digest: IntegrityDigest::from_bytes([1; 32]),
            })
            .unwrap();
        let before = aggregate.clone();

        let error = aggregate
            .apply_payload(&TaskRunEvent::LoopCheckpointCommitted {
                checkpoint_id,
                event_position: 5,
                integrity_digest: IntegrityDigest::from_bytes([1; 32]),
            })
            .unwrap_err();

        assert_eq!(
            error,
            DomainError::LoopInvariantViolation {
                violation: LoopInvariantViolation::CheckpointMismatch,
            }
        );
        assert_eq!(aggregate, before);
    }

    #[test]
    fn replay_rejects_torn_loop_checkpoint_batch() {
        let taskrun_id: TaskRunId = VALID_UUID.parse().unwrap();
        let events = vec![
            make_envelope(1, TaskRunEvent::TaskRunCreated, taskrun_id),
            make_envelope(2, TaskRunEvent::TaskRunQueued, taskrun_id),
            make_envelope(3, TaskRunEvent::TaskRunAdmitted, taskrun_id),
            make_envelope(
                4,
                TaskRunEvent::AttemptStarted {
                    attempt_id: ATTEMPT_ID.parse().unwrap(),
                },
                taskrun_id,
            ),
            make_envelope(
                5,
                TaskRunEvent::LoopCheckpointStarted {
                    checkpoint_id: WORKSPACE_ID.parse().unwrap(),
                    event_position: 5,
                    integrity_digest: IntegrityDigest::from_bytes([4; 32]),
                },
                taskrun_id,
            ),
        ];

        assert_eq!(
            TaskRun::replay(&events).unwrap_err(),
            DomainError::CorruptCommandBatch
        );
    }

    #[test]
    fn test_invalid_transition_attempt_started_from_created() {
        let mut agg = create_aggregate();
        let aid: AttemptId = ATTEMPT_ID.parse().unwrap();
        let err = agg.apply_payload(&TaskRunEvent::AttemptStarted { attempt_id: aid });
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            DomainError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn test_queue_from_created() {
        let mut agg = create_aggregate();
        let drafts = agg.decide(TaskRunCommand::Queue).unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(*drafts[0].payload(), TaskRunEvent::TaskRunQueued);
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        assert_eq!(agg.state(), TaskRunState::Queued);
    }

    #[test]
    fn test_queue_from_queued_is_invalid() {
        let mut agg = create_aggregate();
        agg.apply_payload(&TaskRunEvent::TaskRunQueued).unwrap();
        let err = agg.decide(TaskRunCommand::Queue).unwrap_err();
        assert!(matches!(err, DomainError::InvalidTransition { .. }));
    }
