    // ══════════════════════════════════════════════════════════════════════════
    // GATE-P5-018: Verification port rejection tests
    // ══════════════════════════════════════════════════════════════════════════

    fn make_running_evaluating_stream() -> Vec<EventEnvelope<TaskRunEvent>> {
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
                    outcome_type: StepOutcomeType::Succeeded,
                    result_ref: Some(
                        ResultRef::new(OTHER.parse().unwrap(), "application/json", digest(15))
                            .unwrap(),
                    ),
                    effect_id: None,
                    evidence_digests: vec![],
                },
            },
        ));
        stream
    }

    #[test]
    fn complete_loop_cycle_rejects_failed_verification_via_port() {
        let stream = make_running_evaluating_stream();
        let taskrun_id: TaskRunId = TASK.parse().unwrap();
        let plan_revision_ref = plan_ref(vec![0]);

        let plan_evaluation_ref = PlanEvaluationRef {
            evaluation_id: OTHER.parse::<PlanEvaluationId>().unwrap(),
            taskrun_id,
            plan_id: plan_revision_ref.plan_id,
            plan_revision: plan_revision_ref.revision,
            evaluated_stream_head: 8,
            result: PlanEvaluationResult::Failed,
            gate_definitions_digest: digest(20),
            evidence_set_digest: digest(21),
            evaluation_digest: digest(22),
        };

        let evaluation = PlanEvaluation {
            reference: plan_evaluation_ref.clone(),
            gate_evaluation_refs: vec![],
            evaluated_at_unix_us: 200,
            superseded_by: None,
        };

        let service = TaskRunService::with_agent_loop_authorities(
            StaticStore { events: stream },
            MissUow,
            NoIds,
            RuntimeAuthorityId("test".into()),
            AgentLoopAuthorities {
                time: NoAuthorities,
                retry_schedule: NoAuthorities,
                wake_evidence: NoAuthorities,
                reconciliation: NoAuthorities,
                verification: StaticVerification { evaluation },
            },
        );

        let context = ApplicationCommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("complete-cycle-1").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let result = service.complete_loop_cycle(
            &context,
            CompleteLoopCycleInput {
                taskrun_id,
                expected_version: 8,
                cycle_id: CYCLE.parse().unwrap(),
                disposition: LoopDisposition::Complete {
                    plan_evaluation_ref,
                },
            },
        );

        assert!(
            matches!(result, Err(ApplicationError::InvalidAuthorityResult)),
            "expected InvalidAuthorityResult for failed evaluation, got {:?}",
            result
        );
    }

    #[test]
    fn complete_loop_cycle_rejects_verification_query_error() {
        let stream = make_running_evaluating_stream();
        let taskrun_id: TaskRunId = TASK.parse().unwrap();
        let plan_revision_ref = plan_ref(vec![0]);

        let plan_evaluation_ref = PlanEvaluationRef {
            evaluation_id: OTHER.parse::<PlanEvaluationId>().unwrap(),
            taskrun_id,
            plan_id: plan_revision_ref.plan_id,
            plan_revision: plan_revision_ref.revision,
            evaluated_stream_head: 8,
            result: PlanEvaluationResult::Passed,
            gate_definitions_digest: digest(20),
            evidence_set_digest: digest(21),
            evaluation_digest: digest(22),
        };

        let service = TaskRunService::with_agent_loop_authorities(
            StaticStore { events: stream },
            MissUow,
            NoIds,
            RuntimeAuthorityId("test".into()),
            AgentLoopAuthorities {
                time: NoAuthorities,
                retry_schedule: NoAuthorities,
                wake_evidence: NoAuthorities,
                reconciliation: NoAuthorities,
                verification: FailingVerification {
                    error: VerificationQueryError::Unavailable,
                },
            },
        );

        let context = ApplicationCommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("complete-cycle-2").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let result = service.complete_loop_cycle(
            &context,
            CompleteLoopCycleInput {
                taskrun_id,
                expected_version: 8,
                cycle_id: CYCLE.parse().unwrap(),
                disposition: LoopDisposition::Complete {
                    plan_evaluation_ref,
                },
            },
        );

        assert!(
            matches!(result, Err(ApplicationError::VerificationRejected(_))),
            "expected VerificationRejected, got {:?}",
            result
        );
    }

    #[test]
    fn complete_loop_cycle_rejects_superseded_verification() {
        let stream = make_running_evaluating_stream();
        let taskrun_id: TaskRunId = TASK.parse().unwrap();
        let plan_revision_ref = plan_ref(vec![0]);

        let plan_evaluation_ref = PlanEvaluationRef {
            evaluation_id: OTHER.parse::<PlanEvaluationId>().unwrap(),
            taskrun_id,
            plan_id: plan_revision_ref.plan_id,
            plan_revision: plan_revision_ref.revision,
            evaluated_stream_head: 8,
            result: PlanEvaluationResult::Passed,
            gate_definitions_digest: digest(20),
            evidence_set_digest: digest(21),
            evaluation_digest: digest(22),
        };

        let superseded: PlanEvaluationId = OTHER.parse().unwrap();
        let evaluation = PlanEvaluation {
            reference: plan_evaluation_ref.clone(),
            gate_evaluation_refs: vec![],
            evaluated_at_unix_us: 200,
            superseded_by: Some(superseded),
        };

        let service = TaskRunService::with_agent_loop_authorities(
            StaticStore { events: stream },
            MissUow,
            NoIds,
            RuntimeAuthorityId("test".into()),
            AgentLoopAuthorities {
                time: NoAuthorities,
                retry_schedule: NoAuthorities,
                wake_evidence: NoAuthorities,
                reconciliation: NoAuthorities,
                verification: StaticVerification { evaluation },
            },
        );

        let context = ApplicationCommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("complete-cycle-3").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let result = service.complete_loop_cycle(
            &context,
            CompleteLoopCycleInput {
                taskrun_id,
                expected_version: 8,
                cycle_id: CYCLE.parse().unwrap(),
                disposition: LoopDisposition::Complete {
                    plan_evaluation_ref,
                },
            },
        );

        assert!(
            matches!(result, Err(ApplicationError::InvalidAuthorityResult)),
            "expected InvalidAuthorityResult for superseded evaluation, got {:?}",
            result
        );
    }
