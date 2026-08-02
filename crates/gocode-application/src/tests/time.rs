    // ══════════════════════════════════════════════════════════════════════════
    // GATE-P5-015: TimePort reading tests
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    fn retry_activation_reads_time_from_port() {
        let mut stream = base_loop_stream();
        stream.push(envelope(
            6,
            TaskRunEvent::ContextCommitted {
                cycle_id: CYCLE.parse().unwrap(),
                manifest_ref: context_ref(),
            },
        ));
        stream.push(envelope(
            7,
            TaskRunEvent::PlanCommitted {
                cycle_id: CYCLE.parse().unwrap(),
                plan_revision_ref: plan_ref(vec![0]),
                input_digest: digest(9),
                output_digest: digest(10),
                expected_proposal_indexes: vec![0],
            },
        ));
        stream.push(envelope(
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
        stream.push(envelope(
            9,
            TaskRunEvent::RetryScheduled {
                ordinal: 1,
                old_attempt_id: ATTEMPT.parse().unwrap(),
                new_attempt_id: ATT2.parse().unwrap(),
                abandoned_cycle_id: CYCLE.parse().unwrap(),
                step_outcome_ref: StepOutcomeRef {
                    cycle_id: CYCLE.parse().unwrap(),
                    proposal_index: 0,
                    step_id: OTHER.parse().unwrap(),
                    outcome_digest: digest(13),
                },
                retry_policy_digest: digest(14),
                budget_reservation_ref: budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 25_100,
            },
        ));

        let taskrun_id: TaskRunId = TASK.parse().unwrap();

        let service = TaskRunService::with_agent_loop_authorities(
            StaticStore { events: stream },
            MissUow,
            StaticIds,
            RuntimeAuthorityId("test".into()),
            AgentLoopAuthorities {
                time: StaticTime { now: 25_200 },
                retry_schedule: NoAuthorities,
                wake_evidence: NoAuthorities,
                reconciliation: NoAuthorities,
                verification: NoAuthorities,
            },
        );

        let context = ApplicationCommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("activate-retry-1").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let result = service.activate_scheduled_retry(
            &context,
            ActivateScheduledRetryInput {
                taskrun_id,
                expected_version: 9,
                retry_ordinal: 1,
            },
        );

        assert!(
            matches!(result, Ok(CommandOutcome::RetryActivated { .. })),
            "expected RetryActivated, got {:?}",
            result
        );
    }

    #[test]
    fn retry_activation_fails_when_not_due_based_on_time_port() {
        let mut stream = base_loop_stream();
        stream.push(envelope(
            6,
            TaskRunEvent::ContextCommitted {
                cycle_id: CYCLE.parse().unwrap(),
                manifest_ref: context_ref(),
            },
        ));
        stream.push(envelope(
            7,
            TaskRunEvent::PlanCommitted {
                cycle_id: CYCLE.parse().unwrap(),
                plan_revision_ref: plan_ref(vec![0]),
                input_digest: digest(9),
                output_digest: digest(10),
                expected_proposal_indexes: vec![0],
            },
        ));
        stream.push(envelope(
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
        stream.push(envelope(
            9,
            TaskRunEvent::RetryScheduled {
                ordinal: 1,
                old_attempt_id: ATTEMPT.parse().unwrap(),
                new_attempt_id: ATT2.parse().unwrap(),
                abandoned_cycle_id: CYCLE.parse().unwrap(),
                step_outcome_ref: StepOutcomeRef {
                    cycle_id: CYCLE.parse().unwrap(),
                    proposal_index: 0,
                    step_id: OTHER.parse().unwrap(),
                    outcome_digest: digest(13),
                },
                retry_policy_digest: digest(14),
                budget_reservation_ref: budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 25_100,
            },
        ));

        let taskrun_id: TaskRunId = TASK.parse().unwrap();

        let service = TaskRunService::with_agent_loop_authorities(
            StaticStore { events: stream },
            MissUow,
            NoIds,
            RuntimeAuthorityId("test".into()),
            AgentLoopAuthorities {
                time: StaticTime { now: 25_000 },
                retry_schedule: NoAuthorities,
                wake_evidence: NoAuthorities,
                reconciliation: NoAuthorities,
                verification: NoAuthorities,
            },
        );

        let context = ApplicationCommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("activate-retry-2").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let result = service.activate_scheduled_retry(
            &context,
            ActivateScheduledRetryInput {
                taskrun_id,
                expected_version: 9,
                retry_ordinal: 1,
            },
        );

        assert!(
            matches!(result, Err(ApplicationError::Domain(_))),
            "expected Domain error (not due), got {:?}",
            result
        );
    }
