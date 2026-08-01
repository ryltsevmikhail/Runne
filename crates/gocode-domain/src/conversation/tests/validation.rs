    #[test]
    fn decide_close_emits_close_event_for_active_conversation() {
        let conversation = conversation(ConversationState::Active);

        let events = conversation
            .decide(ConversationCommand::Close)
            .expect("active conversation can close");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload(), &ConversationEvent::ConversationClosed);
        assert_eq!(events[0].aggregate_id(), &conversation_aggregate_id());
        assert_eq!(events[0].correlation_id(), &conversation_aggregate_id());
    }

    #[test]
    fn decide_rejects_closing_closed_conversation() {
        let conversation = conversation(ConversationState::Closed);

        assert!(matches!(
            conversation.decide(ConversationCommand::Close),
            Err(ConversationError::AlreadyClosed)
        ));
    }

    #[test]
    fn apply_rejects_creation_after_create_without_mutation() {
        let mut conversation = conversation(ConversationState::Active);
        let event = make_envelope(
            2,
            ConversationEvent::ConversationCreated {
                workspace_id: other_workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::InvalidTransition {
                from: ConversationState::Active,
                event: ConversationEventKind::ConversationCreated,
            })
        );
        assert_eq!(conversation.state, ConversationState::Active);
        assert_eq!(conversation.workspace_id, workspace_id());
    }

    #[test]
    fn apply_rejects_creation_after_close_without_mutation() {
        let mut conversation = conversation(ConversationState::Closed);
        let event = make_envelope(
            3,
            ConversationEvent::ConversationCreated {
                workspace_id: other_workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::InvalidTransition {
                from: ConversationState::Closed,
                event: ConversationEventKind::ConversationCreated,
            })
        );
        assert_eq!(conversation.state, ConversationState::Closed);
        assert_eq!(conversation.workspace_id, workspace_id());
    }

    #[test]
    fn apply_rejects_non_conversation_aggregate_id() {
        let mut conversation = conversation(ConversationState::Active);
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            2,
            ConversationEvent::ConversationClosed,
            AggregateId::TaskRun(taskrun_id),
            conversation_aggregate_id(),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::AggregateIdMismatch {
                expected: conversation_aggregate_id(),
                actual: AggregateId::TaskRun(taskrun_id),
            })
        );
        assert_eq!(conversation.state, ConversationState::Active);
    }

    #[test]
    fn apply_rejects_non_conversation_correlation_id() {
        let mut conversation = conversation(ConversationState::Active);
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            2,
            ConversationEvent::ConversationClosed,
            conversation_aggregate_id(),
            AggregateId::TaskRun(taskrun_id),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::AggregateIdMismatch {
                expected: conversation_aggregate_id(),
                actual: AggregateId::TaskRun(taskrun_id),
            })
        );
        assert_eq!(conversation.state, ConversationState::Active);
    }

    #[test]
    fn replay_rejects_non_conversation_aggregate_id() {
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            AggregateId::TaskRun(taskrun_id),
            conversation_aggregate_id(),
        );

        assert!(matches!(
            Conversation::replay(&[event]),
            Err(ConversationError::AggregateIdMismatch { .. })
        ));
    }

    #[test]
    fn replay_rejects_non_conversation_correlation_id() {
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            AggregateId::TaskRun(taskrun_id),
        );

        assert_eq!(
            Conversation::replay(&[event]),
            Err(ConversationError::AggregateIdMismatch {
                expected: conversation_aggregate_id(),
                actual: AggregateId::TaskRun(taskrun_id),
            })
        );
    }

    #[test]
    fn replay_rejects_empty_stream_and_sequence_errors() {
        assert_eq!(
            Conversation::replay(&[]),
            Err(ConversationError::MissingCreationEvent)
        );

        let event = make_envelope(
            2,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        assert_eq!(
            Conversation::replay(&[event]),
            Err(ConversationError::InvalidInitialSequence {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn replay_rejects_sequence_gap_and_duplicate_creation() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let gap = make_envelope(
            3,
            ConversationEvent::ConversationClosed,
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        assert_eq!(
            Conversation::replay(&[created.clone(), gap]),
            Err(ConversationError::SequenceGap {
                expected: 2,
                actual: 3,
            })
        );

        let duplicate = make_envelope(
            2,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        assert_eq!(
            Conversation::replay(&[created, duplicate]),
            Err(ConversationError::DuplicateCreationEvent {
                conversation_id: conversation_id(),
            })
        );
    }
