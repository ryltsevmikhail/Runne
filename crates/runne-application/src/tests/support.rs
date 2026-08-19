    use super::*;
    use crate::fingerprint::CommandFingerprint;
    use crate::ports::*;
    use runne_domain::event::Actor;
    use runne_domain::id::{
        AttemptId, CommandId, ConversationId, EventId, IdempotencyKey, TaskRunId,
    };

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    struct DuplicateStore;
    impl EventStore for DuplicateStore {
        fn load_task_run(&self, _: TaskRunId) -> Result<LoadedStream, EventStoreError> {
            panic!("duplicate lookup must precede stream loading")
        }
    }

    struct DuplicateUnitOfWork {
        outcome: CommandOutcome,
    }
    impl UnitOfWork for DuplicateUnitOfWork {
        fn lookup_receipt(
            &self,
            _: CommandId,
            _: &IdempotencyKey,
            _: &IdempotencyScope,
            _: &CommandFingerprint,
        ) -> Result<ReceiptLookup, CommitError> {
            Ok(ReceiptLookup::Duplicate {
                stored_result: self.outcome.clone(),
            })
        }

        fn commit(&self, _: CommandCommit) -> Result<CommitResult, CommitError> {
            panic!("duplicate command must not commit")
        }
    }

    struct NoIds;
    impl IdGenerator for NoIds {
        fn next_taskrun_id(&self) -> Result<TaskRunId, IdGenerationError> {
            panic!("duplicate command must not generate IDs")
        }
        fn next_conversation_id(&self) -> Result<ConversationId, IdGenerationError> {
            panic!("duplicate command must not generate IDs")
        }
        fn next_attempt_id(&self) -> Result<AttemptId, IdGenerationError> {
            panic!("duplicate command must not generate IDs")
        }
        fn next_event_ids(&self, _: usize) -> Result<Vec<EventId>, IdGenerationError> {
            panic!("duplicate command must not generate event IDs")
        }
    }

    struct NoAuthorities;
    impl TimePort for NoAuthorities {
        fn now_unix_us(&self) -> Result<i64, TimeError> {
            panic!("duplicate activation must not read time")
        }
    }
    impl RetrySchedulePort for NoAuthorities {
        fn prepare(
            &self,
            _: TaskRunId,
            _: AttemptId,
            _: u64,
            _: &runne_domain::agent_loop::StepOutcomeRef,
            _: &runne_domain::id::IntegrityDigest,
            _: &runne_domain::reference::BudgetReservationRef,
            _: i64,
        ) -> Result<PreparedRetrySchedule, RetryScheduleError> {
            panic!("unexpected retry preparation")
        }
    }
    impl WakeEvidenceQueryPort for NoAuthorities {
        fn validate_current(
            &self,
            _: &runne_domain::agent_loop::WakeEvidenceRef,
            _: TaskRunId,
            _: runne_domain::id::CycleId,
            _: &runne_domain::agent_loop::WakeCondition,
        ) -> Result<(), WakeEvidenceError> {
            panic!("unexpected wake validation")
        }
    }
    impl ReconciliationQueryPort for NoAuthorities {
        fn validate_current(
            &self,
            _: &runne_domain::recovery::ReconciliationResultRef,
            _: TaskRunId,
            _: AttemptId,
            _: u64,
            _: u64,
        ) -> Result<(), ReconciliationError> {
            panic!("unexpected reconciliation validation")
        }
    }
    impl VerificationQueryPort for NoAuthorities {
        fn get_exact(
            &self,
            _: &runne_domain::verification::PlanEvaluationRef,
        ) -> Result<PlanEvaluation, VerificationQueryError> {
            panic!("unexpected verification lookup")
        }
    }
