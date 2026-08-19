    #[test]
    fn resume_loop_wait_rejects_invalid_wake_evidence_via_port() {
        let mut stream = base_loop_stream();
        let wake_condition = WakeCondition {
            kind: WakeConditionKind::Approval,
            condition_ref: "approval:1".into(),
            condition_digest: digest(11),
        };
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
                plan_revision_ref: plan_ref(vec![]),
                input_digest: digest(9),
                output_digest: digest(10),
                expected_proposal_indexes: vec![],
            },
        ));
        stream.push(envelope(
            8,
            TaskRunEvent::LoopCycleCompleted {
                cycle_id: CYCLE.parse().unwrap(),
                attempt_id: ATTEMPT.parse().unwrap(),
                disposition: LoopDisposition::Wait {
                    reason: "approval".into(),
                    wake_condition: wake_condition.clone(),
                },
            },
        ));
        stream.push(envelope(9, TaskRunEvent::WaitStarted));

        let taskrun_id: TaskRunId = TASK.parse().unwrap();

        let service = TaskRunService::with_agent_loop_authorities(
            StaticStore { events: stream },
            MissUow,
            NoIds,
            RuntimeAuthorityId("test".into()),
            AgentLoopAuthorities {
                time: NoAuthorities,
                retry_schedule: NoAuthorities,
                wake_evidence: RejectingWake,
                reconciliation: NoAuthorities,
                verification: NoAuthorities,
            },
        );

        let context = ApplicationCommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("resume-wake-1").unwrap(),
            principal_id: PrincipalId("principal".into()),
            actor: Actor::new("principal").unwrap(),
        };

        let result = service.resume_loop_wait(
            &context,
            ResumeLoopWaitInput {
                taskrun_id,
                expected_version: 9,
                wake_evidence_ref: WakeEvidenceRef {
                    cycle_id: CYCLE.parse().unwrap(),
                    condition_digest: digest(11),
                    source: WakeEvidenceSource::Approval,
                    evidence_id: OTHER.parse().unwrap(),
                    evidence_digest: digest(12),
                    observed_at_unix_us: 100,
                    authority_revision: "approval-v1".into(),
                },
            },
        );

        assert!(
            matches!(result, Err(ApplicationError::WakeEvidenceRejected(_))),
            "expected WakeEvidenceRejected, got {:?}",
            result
        );
    }
