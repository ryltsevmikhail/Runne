    #[test]
    fn duplicate_retry_activation_returns_original_without_time_or_id_reads() {
        let taskrun_id: TaskRunId = UUID.parse().unwrap();
        let attempt_id: AttemptId = UUID.parse().unwrap();
        let expected = CommandOutcome::RetryActivated {
            taskrun_id,
            attempt_id,
            new_version: 42,
        };
        let service = TaskRunService::with_agent_loop_authorities(
            DuplicateStore,
            DuplicateUnitOfWork {
                outcome: expected.clone(),
            },
            NoIds,
            RuntimeAuthorityId("runtime".into()),
            AgentLoopAuthorities {
                time: NoAuthorities,
                retry_schedule: NoAuthorities,
                wake_evidence: NoAuthorities,
                reconciliation: NoAuthorities,
                verification: NoAuthorities,
            },
        );
        let context = ApplicationCommandContext {
            command_id: UUID.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("activate-1").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let actual = service
            .activate_scheduled_retry(
                &context,
                ActivateScheduledRetryInput {
                    taskrun_id,
                    expected_version: 41,
                    retry_ordinal: 1,
                },
            )
            .unwrap();

        assert_eq!(actual, expected);
    }
