    #[test]
    fn decide_create_sets_conversation_identity_for_aggregate_and_correlation() {
        let draft = Conversation::decide_create(conversation_id(), workspace_id());

        assert_eq!(draft.aggregate_id(), &conversation_aggregate_id());
        assert_eq!(draft.correlation_id(), &conversation_aggregate_id());
        assert_eq!(
            draft.payload(),
            &ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            }
        );
    }

    #[test]
    fn replay_created_conversation_is_active() {
        let events = [make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        )];

        let conversation = Conversation::replay(&events).expect("valid conversation stream");

        assert_eq!(conversation.id, conversation_id());
        assert_eq!(conversation.workspace_id, workspace_id());
        assert_eq!(conversation.state, ConversationState::Active);
    }

    #[test]
    fn replay_close_transitions_to_closed() {
        let events = [
            make_envelope(
                1,
                ConversationEvent::ConversationCreated {
                    workspace_id: workspace_id(),
                },
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
            make_envelope(
                2,
                ConversationEvent::ConversationClosed,
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
        ];

        let conversation = Conversation::replay(&events).expect("valid conversation stream");

        assert_eq!(conversation.state, ConversationState::Closed);
    }

    #[test]
    fn user_and_assistant_messages_are_sensitive_and_replay_as_one_exchange() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let aggregate = Conversation::replay(std::slice::from_ref(&created)).unwrap();
        let user_draft = aggregate
            .decide(ConversationCommand::AppendUserMessage {
                message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("hello").unwrap(),
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(user_draft.sensitivity(), &Sensitivity::Sensitive);
        let user = make_envelope(
            2,
            user_draft.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let aggregate = Conversation::replay(&[created.clone(), user.clone()]).unwrap();
        assert_eq!(
            aggregate.active_generation(),
            Some(&ActiveTextGeneration {
                user_message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
            })
        );

        let assistant_draft = aggregate
            .decide(ConversationCommand::AppendAssistantMessage {
                message_id: assistant_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("world").unwrap(),
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(assistant_draft.sensitivity(), &Sensitivity::Sensitive);
        let assistant = make_envelope(
            3,
            assistant_draft.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        let replayed = Conversation::replay(&[created, user, assistant]).unwrap();
        assert_eq!(replayed.active_generation(), None);
        assert_eq!(replayed.messages().len(), 2);
        assert_eq!(replayed.messages()[0].role, MessageRole::User);
        assert_eq!(replayed.messages()[0].text.as_str(), "hello");
        assert_eq!(replayed.messages()[1].role, MessageRole::Assistant);
        assert_eq!(replayed.messages()[1].text.as_str(), "world");
    }

    #[test]
    fn assistant_message_must_match_the_active_taskrun_and_attempt() {
        let events = [
            make_envelope(
                1,
                ConversationEvent::ConversationCreated {
                    workspace_id: workspace_id(),
                },
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
            make_envelope(
                2,
                ConversationEvent::UserMessageAppended {
                    message_id: user_message_id(),
                    taskrun_id: taskrun_id(),
                    attempt_id: attempt_id(),
                    text: MessageText::new("hello").unwrap(),
                },
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
        ];
        let aggregate = Conversation::replay(&events).unwrap();

        assert!(matches!(
            aggregate.decide(ConversationCommand::AppendAssistantMessage {
                message_id: assistant_message_id(),
                taskrun_id: "018f2e3a-7000-7000-8000-000000000007".parse().unwrap(),
                attempt_id: attempt_id(),
                text: MessageText::new("wrong").unwrap(),
            }),
            Err(ConversationError::GenerationMismatch)
        ));
        assert_eq!(aggregate.messages().len(), 1);
    }

    #[test]
    fn provider_output_rejection_releases_generation_without_assistant_message() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let user = make_envelope(
            2,
            ConversationEvent::UserMessageAppended {
                message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("hello").unwrap(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let aggregate = Conversation::replay(&[created.clone(), user.clone()]).unwrap();

        let rejection = aggregate
            .decide(ConversationCommand::FailGeneration {
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                reason: GenerationFailureReason::ProviderOutputRejected,
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            rejection.payload(),
            &ConversationEvent::GenerationFailed {
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                reason: GenerationFailureReason::ProviderOutputRejected,
            }
        );
        assert_eq!(rejection.sensitivity(), &Sensitivity::Public);
        let rejection = make_envelope(
            3,
            rejection.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        let replayed = Conversation::replay(&[created, user, rejection]).unwrap();
        assert_eq!(replayed.active_generation(), None);
        assert_eq!(replayed.messages().len(), 1);
        assert_eq!(replayed.messages()[0].role, MessageRole::User);
    }

    #[test]
    fn explicit_unknown_supersession_releases_only_the_exact_active_generation() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let user = make_envelope(
            2,
            ConversationEvent::UserMessageAppended {
                message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("run command").unwrap(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let active = Conversation::replay(&[created.clone(), user.clone()]).unwrap();
        let digest = IntegrityDigest::from_bytes([0x5a; 32]);
        let successor = "018f0000-0000-7000-8000-000000000002".parse().unwrap();
        let draft = active
            .decide(ConversationCommand::SupersedeGenerationUnknown {
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                successor_taskrun_id: successor,
                acknowledgement_digest: digest,
            })
            .unwrap()
            .remove(0);
        assert_eq!(draft.sensitivity(), &Sensitivity::Public);
        let marker = make_envelope(
            3,
            draft.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        let replayed = Conversation::replay(&[created, user, marker]).unwrap();
        assert_eq!(replayed.active_generation(), None);
        assert_eq!(replayed.messages().len(), 1);
    }
