    // ══════════════════════════════════════════════════════════════════════════
    // Service-level authority port tests and helpers
    // ══════════════════════════════════════════════════════════════════════════

    use runne_domain::agent_loop::{
        LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType, WakeCondition,
        WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource,
    };
    use runne_domain::context::ContextManifestRef;
    use runne_domain::event::{
        CommandContext, DomainEventDraft, EventEnvelope, Sensitivity, materialize_batch,
    };
    use runne_domain::id::{AggregateId, CycleId, IntegrityDigest, PlanEvaluationId};
    use runne_domain::plan::PlanRevisionRef;
    use runne_domain::reference::{BudgetReservationRef, ResultRef};
    use runne_domain::task_run::TaskRunEvent;
    use runne_domain::timestamp::Timestamp;
    use runne_domain::verification::{PlanEvaluationRef, PlanEvaluationResult};

    const TASK: &str = "018f2e3a-7000-7000-8000-000000000001";
    const ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000002";
    const CYCLE: &str = "018f2e3a-7000-7000-8000-000000000003";
    const OTHER: &str = "018f2e3a-7000-7000-8000-000000000004";
    const ATT2: &str = "018f2e3a-7000-7000-8000-000000000005";

    fn digest(byte: u8) -> IntegrityDigest {
        IntegrityDigest::from_bytes([byte; 32])
    }

    fn context_ref() -> ContextManifestRef {
        ContextManifestRef {
            manifest_id: OTHER.parse().unwrap(),
            taskrun_id: TASK.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            cycle_id: CYCLE.parse().unwrap(),
            revision: 1,
            policy_revision: "context-v1".into(),
            integrity_digest: digest(1),
        }
    }

    fn budget_ref() -> BudgetReservationRef {
        BudgetReservationRef {
            reservation_id: OTHER.parse().unwrap(),
            taskrun_id: TASK.parse().unwrap(),
            attempt_id: ATTEMPT.parse().unwrap(),
            retry_ordinal: 1,
            reservation_digest: digest(2),
        }
    }

    fn plan_ref(indexes: Vec<u32>) -> PlanRevisionRef {
        PlanRevisionRef {
            plan_id: OTHER.parse().unwrap(),
            taskrun_id: TASK.parse().unwrap(),
            cycle_id: CYCLE.parse().unwrap(),
            revision: 1,
            context_manifest_ref: context_ref(),
            expected_proposal_indexes: indexes,
            proposal_batch_digest: digest(3),
            planning_policy_ref: ResultRef::new(
                OTHER.parse().unwrap(),
                "application/json",
                digest(4),
            )
            .unwrap(),
            planning_budget_ref: budget_ref(),
            parent_ref: None,
            integrity_digest: digest(5),
        }
    }

    fn envelope(sequence: u64, payload: TaskRunEvent) -> EventEnvelope<TaskRunEvent> {
        let taskrun_id: TaskRunId = TASK.parse().unwrap();
        let aggregate_id = AggregateId::TaskRun(taskrun_id);
        let draft = DomainEventDraft::new(
            aggregate_id.clone(),
            aggregate_id,
            1,
            Sensitivity::Sensitive,
            payload,
        );
        let command = CommandContext {
            command_id: TASK.parse().unwrap(),
            idempotency_key: IdempotencyKey::new("svc-test").unwrap(),
            actor: Actor::new("svc-test").unwrap(),
        };
        let event_id: EventId = OTHER.parse().unwrap();
        materialize_batch(vec![draft], &[event_id], None, &command)
            .unwrap()
            .remove(0)
            .into_envelope(
                sequence,
                Timestamp::from_unix_micros(sequence as i64),
                digest(0),
            )
    }

    fn base_loop_stream() -> Vec<EventEnvelope<TaskRunEvent>> {
        vec![
            envelope(1, TaskRunEvent::TaskRunCreated),
            envelope(2, TaskRunEvent::TaskRunQueued),
            envelope(3, TaskRunEvent::TaskRunAdmitted),
            envelope(
                4,
                TaskRunEvent::AttemptStarted {
                    attempt_id: ATTEMPT.parse().unwrap(),
                },
            ),
            envelope(
                5,
                TaskRunEvent::LoopCycleStarted {
                    cycle_id: CYCLE.parse().unwrap(),
                    attempt_id: ATTEMPT.parse().unwrap(),
                    sequence: 0,
                    parent_cycle_id: None,
                },
            ),
        ]
    }

    // ── Mock types ───────────────────────────────────────────────────────────

    struct StaticStore {
        events: Vec<EventEnvelope<TaskRunEvent>>,
    }
    impl EventStore for StaticStore {
        fn load_task_run(&self, _: TaskRunId) -> Result<LoadedStream, EventStoreError> {
            let version = self.events.len() as u64;
            Ok(LoadedStream {
                current_version: version,
                last_event_id: self.events.last().map(|e| *e.event_id()),
                events: self.events.clone(),
            })
        }
    }

    struct MissUow;
    impl UnitOfWork for MissUow {
        fn lookup_receipt(
            &self,
            _: CommandId,
            _: &IdempotencyKey,
            _: &IdempotencyScope,
            _: &CommandFingerprint,
        ) -> Result<ReceiptLookup, CommitError> {
            Ok(ReceiptLookup::Miss)
        }
        fn commit(&self, payload: CommandCommit) -> Result<CommitResult, CommitError> {
            // Success path for tests that go through decide + commit.
            let new_version = payload.expected_version + payload.events.len() as u64;
            Ok(CommitResult::Committed { new_version })
        }
    }

    struct StaticIds;
    impl IdGenerator for StaticIds {
        fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
            panic!("unexpected next_taskrun_id")
        }
        fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
            panic!("unexpected next_conversation_id")
        }
        fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
            panic!("unexpected next_attempt_id")
        }
        fn next_event_ids(&self, count: usize) -> Result<Vec<EventId>, IdGenerationError> {
            let eid: EventId = OTHER.parse().unwrap();
            Ok((0..count).map(|_| eid).collect())
        }
    }

    struct RejectingWake;
    impl WakeEvidenceQueryPort for RejectingWake {
        fn validate_current(
            &self,
            _: &WakeEvidenceRef,
            _: TaskRunId,
            _: CycleId,
            _: &WakeCondition,
        ) -> Result<(), WakeEvidenceError> {
            Err(WakeEvidenceError::Forged)
        }
    }

    struct StaticTime {
        now: i64,
    }
    impl TimePort for StaticTime {
        fn now_unix_us(&self) -> Result<i64, TimeError> {
            Ok(self.now)
        }
    }

    struct StaticVerification {
        evaluation: PlanEvaluation,
    }
    impl VerificationQueryPort for StaticVerification {
        fn get_exact(
            &self,
            _: &PlanEvaluationRef,
        ) -> Result<PlanEvaluation, VerificationQueryError> {
            Ok(self.evaluation.clone())
        }
    }

    struct FailingVerification {
        error: VerificationQueryError,
    }
    impl VerificationQueryPort for FailingVerification {
        fn get_exact(
            &self,
            _: &PlanEvaluationRef,
        ) -> Result<PlanEvaluation, VerificationQueryError> {
            Err(self.error.clone())
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GATE-P5-008: Wake evidence rejection
    // ══════════════════════════════════════════════════════════════════════════
