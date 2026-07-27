//! Public application facade — the only entry point for callers.
//!
//! [`TaskRunService`] owns the pipeline and exposes five typed use cases.

use gocode_domain::agent_loop::{LoopCheckpointBody, LoopDisposition};
use gocode_domain::command::TaskRunCommand;
use gocode_domain::task_run::TaskRunState;
use gocode_domain::verification::PlanEvaluationResult;

use crate::commands::{
    ActivateScheduledRetryInput, AdmitTaskRunInput, CommandOutcome, CommitContextInput,
    CommitLoopCheckpointInput, CommitPlanInput, CommitRecoveryResumeInput, CompleteLoopCycleInput,
    CompleteTaskRunInput, CreateNextCycleInput, CreateTaskRunInput, QueueTaskRunInput,
    RecordStepOutcomeInput, ResumeLoopWaitInput, ScheduleRetryInput, StartAttemptInput,
    StartLoopCycleInput,
};
use crate::errors::ApplicationError;
use crate::fingerprint::{CommandFingerprint, checkpoint_body_digest};
use crate::pipeline::Pipeline;
use crate::ports::{
    ApplicationCommandContext, EventStore, IdGenerator, OperationTag, ReconciliationQueryPort,
    RetrySchedulePort, RuntimeAuthorityId, TimePort, UnitOfWork, VerificationQueryPort,
    WakeEvidenceQueryPort,
};

pub struct NoAgentLoopAuthorities;

pub struct AgentLoopAuthorities<T, R, W, C, V> {
    pub time: T,
    pub retry_schedule: R,
    pub wake_evidence: W,
    pub reconciliation: C,
    pub verification: V,
}

pub struct TaskRunService<E, U, I, A = NoAgentLoopAuthorities> {
    pipeline: Pipeline<E, U, I>,
    authorities: A,
}

impl<E: EventStore, U: UnitOfWork, I: IdGenerator> TaskRunService<E, U, I, NoAgentLoopAuthorities> {
    pub fn new(
        event_store: E,
        unit_of_work: U,
        id_generator: I,
        runtime_authority_id: RuntimeAuthorityId,
    ) -> Self {
        Self {
            pipeline: Pipeline {
                event_store,
                unit_of_work,
                id_generator,
                runtime_authority_id,
            },
            authorities: NoAgentLoopAuthorities,
        }
    }

    pub fn with_agent_loop_authorities<T, R, W, C, V>(
        event_store: E,
        unit_of_work: U,
        id_generator: I,
        runtime_authority_id: RuntimeAuthorityId,
        authorities: AgentLoopAuthorities<T, R, W, C, V>,
    ) -> TaskRunService<E, U, I, AgentLoopAuthorities<T, R, W, C, V>> {
        TaskRunService {
            pipeline: Pipeline {
                event_store,
                unit_of_work,
                id_generator,
                runtime_authority_id,
            },
            authorities,
        }
    }
}

impl<E: EventStore, U: UnitOfWork, I: IdGenerator, A> TaskRunService<E, U, I, A> {
    pub fn create_task_run(
        &self,
        context: &ApplicationCommandContext,
        input: CreateTaskRunInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fp = CommandFingerprint::for_create(&input.conversation_id, &input.workspace_id);
        self.pipeline.execute_create(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.conversation_id,
            input.workspace_id,
            &fp,
        )
    }

    pub fn queue_task_run(
        &self,
        context: &ApplicationCommandContext,
        input: QueueTaskRunInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fp = CommandFingerprint::for_queue(&input.taskrun_id, input.expected_version);
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::Queue,
            &fp,
            |new_version| CommandOutcome::TaskRunQueued {
                taskrun_id: input.taskrun_id,
                new_version,
            },
            OperationTag::Queue,
        )
    }

    pub fn admit_task_run(
        &self,
        context: &ApplicationCommandContext,
        input: AdmitTaskRunInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fp = CommandFingerprint::for_admit(&input.taskrun_id, input.expected_version);
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::Admit,
            &fp,
            |new_version| CommandOutcome::TaskRunAdmitted {
                taskrun_id: input.taskrun_id,
                new_version,
            },
            OperationTag::Admit,
        )
    }

    pub fn start_attempt(
        &self,
        context: &ApplicationCommandContext,
        input: StartAttemptInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fp = CommandFingerprint::for_start_attempt(&input.taskrun_id, input.expected_version);
        let attempt_id = self
            .pipeline
            .id_generator
            .next_attempt_id()
            .map_err(ApplicationError::IdGenerationFailed)?;
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::StartAttempt { attempt_id },
            &fp,
            |new_version| CommandOutcome::AttemptStarted {
                taskrun_id: input.taskrun_id,
                attempt_id,
                new_version,
            },
            OperationTag::StartAttempt,
        )
    }

    pub fn complete_task_run(
        &self,
        context: &ApplicationCommandContext,
        input: CompleteTaskRunInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fp = CommandFingerprint::for_complete(
            &input.taskrun_id,
            &input.result,
            input.expected_version,
        )
        .map_err(ApplicationError::InvalidCommandFingerprint)?;
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::Complete {
                result: input.result,
            },
            &fp,
            |new_version| CommandOutcome::TaskRunCompleted {
                taskrun_id: input.taskrun_id,
                new_version,
            },
            OperationTag::Complete,
        )
    }
}

impl<E, U, I, T, R, W, C, V> TaskRunService<E, U, I, AgentLoopAuthorities<T, R, W, C, V>>
where
    E: EventStore,
    U: UnitOfWork,
    I: IdGenerator,
    T: TimePort,
    R: RetrySchedulePort,
    W: WakeEvidenceQueryPort,
    C: ReconciliationQueryPort,
    V: VerificationQueryPort,
{
    pub fn start_loop_cycle(
        &self,
        context: &ApplicationCommandContext,
        input: StartLoopCycleInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_start_loop_cycle(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::StartLoopCycle,
            |_| {
                let cycle_id = self
                    .pipeline
                    .id_generator
                    .next_cycle_id()
                    .map_err(ApplicationError::IdGenerationFailed)?;
                Ok((
                    TaskRunCommand::StartLoopCycle { cycle_id },
                    move |new_version| CommandOutcome::CycleStarted {
                        taskrun_id: input.taskrun_id,
                        cycle_id,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn commit_context(
        &self,
        context: &ApplicationCommandContext,
        input: CommitContextInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_commit_context(&input);
        let cycle_id = input.cycle_id;
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::CommitContext {
                cycle_id,
                manifest_ref: input.manifest_ref,
            },
            &fingerprint,
            move |new_version| CommandOutcome::ContextCommitted {
                taskrun_id: input.taskrun_id,
                cycle_id,
                new_version,
            },
            OperationTag::CommitContext,
        )
    }

    pub fn commit_plan(
        &self,
        context: &ApplicationCommandContext,
        input: CommitPlanInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_commit_plan(&input);
        let plan_ref = input.plan_revision_ref.clone();
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::CommitPlan {
                cycle_id: input.cycle_id,
                plan_revision_ref: input.plan_revision_ref,
                input_digest: input.input_digest,
                output_digest: input.output_digest,
                expected_proposal_indexes: input.expected_proposal_indexes,
            },
            &fingerprint,
            move |new_version| CommandOutcome::PlanCommitted {
                taskrun_id: input.taskrun_id,
                plan_ref: Box::new(plan_ref),
                new_version,
            },
            OperationTag::CommitPlan,
        )
    }

    pub fn record_step_outcome(
        &self,
        context: &ApplicationCommandContext,
        input: RecordStepOutcomeInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_record_step_outcome(&input);
        let step_id = input.outcome.step_id;
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::RecordStepOutcome {
                cycle_id: input.cycle_id,
                outcome: input.outcome,
            },
            &fingerprint,
            move |new_version| CommandOutcome::StepOutcomeRecorded {
                taskrun_id: input.taskrun_id,
                step_id,
                new_version,
            },
            OperationTag::RecordStepOutcome,
        )
    }

    pub fn complete_loop_cycle(
        &self,
        context: &ApplicationCommandContext,
        input: CompleteLoopCycleInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_complete_loop_cycle(&input);
        let final_state = match input.disposition {
            LoopDisposition::Continue => TaskRunState::Running,
            LoopDisposition::Wait { .. } => TaskRunState::Waiting,
            LoopDisposition::Complete { .. } => TaskRunState::Succeeded,
            LoopDisposition::Fail { .. } => TaskRunState::Failed,
        };
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::CompleteLoopCycle,
            |aggregate| {
                if let LoopDisposition::Complete {
                    plan_evaluation_ref,
                } = &input.disposition
                {
                    let evaluation = self
                        .authorities
                        .verification
                        .get_exact(plan_evaluation_ref)
                        .map_err(ApplicationError::VerificationRejected)?;
                    let active_plan = aggregate
                        .active_cycle()
                        .and_then(|cycle| cycle.plan_revision_ref.as_ref())
                        .ok_or(ApplicationError::InvalidAuthorityResult)?;
                    if evaluation.reference != *plan_evaluation_ref
                        || evaluation.superseded_by.is_some()
                        || evaluation.reference.result != PlanEvaluationResult::Passed
                        || evaluation.reference.taskrun_id != input.taskrun_id
                        || evaluation.reference.plan_id != active_plan.plan_id
                        || evaluation.reference.plan_revision != active_plan.revision
                        || evaluation.reference.evaluated_stream_head != input.expected_version
                    {
                        return Err(ApplicationError::InvalidAuthorityResult);
                    }
                }
                let cycle_id = input.cycle_id;
                Ok((
                    TaskRunCommand::CompleteLoopCycle {
                        cycle_id,
                        disposition: input.disposition,
                    },
                    move |new_version| CommandOutcome::LoopDispositionCommitted {
                        taskrun_id: input.taskrun_id,
                        cycle_id,
                        final_state,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn create_next_cycle(
        &self,
        context: &ApplicationCommandContext,
        input: CreateNextCycleInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_create_next_cycle(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::CreateNextCycle,
            |_| {
                let successor_cycle_id = self
                    .pipeline
                    .id_generator
                    .next_cycle_id()
                    .map_err(ApplicationError::IdGenerationFailed)?;
                Ok((
                    TaskRunCommand::CreateNextCycle {
                        parent_cycle_id: input.parent_cycle_id,
                        successor_cycle_id,
                    },
                    move |new_version| CommandOutcome::NextCycleAllocated {
                        taskrun_id: input.taskrun_id,
                        successor_cycle_id,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn resume_loop_wait(
        &self,
        context: &ApplicationCommandContext,
        input: ResumeLoopWaitInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_resume_loop_wait(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::ResumeLoopWait,
            |aggregate| {
                let pending = aggregate
                    .pending_loop_wait()
                    .ok_or(ApplicationError::InvalidAuthorityResult)?;
                self.authorities
                    .wake_evidence
                    .validate_current(
                        &input.wake_evidence_ref,
                        input.taskrun_id,
                        pending.cycle_id,
                        &pending.wake_condition,
                    )
                    .map_err(ApplicationError::WakeEvidenceRejected)?;
                let cycle_id = input.wake_evidence_ref.cycle_id;
                Ok((
                    TaskRunCommand::ResumeLoopWait {
                        wake_evidence_ref: input.wake_evidence_ref,
                    },
                    move |new_version| CommandOutcome::LoopWaitResumed {
                        taskrun_id: input.taskrun_id,
                        cycle_id,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn schedule_retry(
        &self,
        context: &ApplicationCommandContext,
        input: ScheduleRetryInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_schedule_retry(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::ScheduleRetry,
            |aggregate| {
                let now = self
                    .authorities
                    .time
                    .now_unix_us()
                    .map_err(ApplicationError::TimePortFailed)?;
                let attempt_id = *aggregate
                    .active_attempt()
                    .ok_or(ApplicationError::InvalidAuthorityResult)?;
                let prepared = self
                    .authorities
                    .retry_schedule
                    .prepare(
                        input.taskrun_id,
                        attempt_id,
                        input.retry_ordinal,
                        &input.step_outcome_ref,
                        &input.retry_policy_digest,
                        &input.budget_reservation_ref,
                        now,
                    )
                    .map_err(ApplicationError::RetryScheduleRejected)?;
                let delay_us = prepared
                    .delay_ms
                    .checked_mul(1_000)
                    .and_then(|delay| i64::try_from(delay).ok())
                    .ok_or(ApplicationError::InvalidAuthorityResult)?;
                let expected_due = now
                    .checked_add(delay_us)
                    .ok_or(ApplicationError::InvalidAuthorityResult)?;
                if prepared.retry_policy_digest != input.retry_policy_digest
                    || prepared.budget_reservation_ref != input.budget_reservation_ref
                    || prepared.due_at_unix_us != expected_due
                {
                    return Err(ApplicationError::InvalidAuthorityResult);
                }
                let new_attempt_id = self
                    .pipeline
                    .id_generator
                    .next_attempt_id()
                    .map_err(ApplicationError::IdGenerationFailed)?;
                let due_at_unix_us = prepared.due_at_unix_us;
                Ok((
                    TaskRunCommand::ScheduleRetry {
                        new_attempt_id,
                        retry_ordinal: input.retry_ordinal,
                        step_outcome_ref: input.step_outcome_ref,
                        retry_policy_digest: prepared.retry_policy_digest,
                        budget_reservation_ref: prepared.budget_reservation_ref,
                        delay_ms: prepared.delay_ms,
                        due_at_unix_us,
                    },
                    move |new_version| CommandOutcome::RetryScheduled {
                        taskrun_id: input.taskrun_id,
                        new_attempt_id,
                        due_at_unix_us,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn activate_scheduled_retry(
        &self,
        context: &ApplicationCommandContext,
        input: ActivateScheduledRetryInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_activate_retry(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::ActivateScheduledRetryAttempt,
            |aggregate| {
                let now_unix_us = self
                    .authorities
                    .time
                    .now_unix_us()
                    .map_err(ApplicationError::TimePortFailed)?;
                let attempt_id = aggregate
                    .pending_retry()
                    .ok_or(ApplicationError::InvalidAuthorityResult)?
                    .new_attempt_id;
                Ok((
                    TaskRunCommand::ActivateScheduledRetryAttempt {
                        retry_ordinal: input.retry_ordinal,
                        now_unix_us,
                    },
                    move |new_version| CommandOutcome::RetryActivated {
                        taskrun_id: input.taskrun_id,
                        attempt_id,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn commit_recovery_resume(
        &self,
        context: &ApplicationCommandContext,
        input: CommitRecoveryResumeInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_commit_recovery_resume(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::CommitRecoveryResume,
            |aggregate| {
                let predecessor_attempt_id = *aggregate
                    .active_attempt()
                    .ok_or(ApplicationError::InvalidAuthorityResult)?;
                self.authorities
                    .reconciliation
                    .validate_current(
                        &input.reconciliation_ref,
                        input.taskrun_id,
                        predecessor_attempt_id,
                        aggregate.recovery_generation(),
                        input.expected_version,
                    )
                    .map_err(ApplicationError::ReconciliationRejected)?;
                let new_attempt_id = self
                    .pipeline
                    .id_generator
                    .next_attempt_id()
                    .map_err(ApplicationError::IdGenerationFailed)?;
                Ok((
                    TaskRunCommand::CommitRecoveryResume {
                        new_attempt_id,
                        context_manifest_ref: input.context_manifest_ref,
                        checkpoint_ref: input.checkpoint_ref,
                        reconciliation_ref: input.reconciliation_ref,
                    },
                    move |new_version| CommandOutcome::RecoveryResumed {
                        taskrun_id: input.taskrun_id,
                        attempt_id: new_attempt_id,
                        new_version,
                    },
                ))
            },
        )
    }

    pub fn commit_loop_checkpoint(
        &self,
        context: &ApplicationCommandContext,
        input: CommitLoopCheckpointInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fingerprint = CommandFingerprint::for_commit_loop_checkpoint(&input);
        let integrity_digest = checkpoint_body_digest(&input);
        self.pipeline.execute_existing_prepared(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            input.taskrun_id,
            input.expected_version,
            &fingerprint,
            OperationTag::CommitLoopCheckpoint,
            |_| {
                let checkpoint_id = self
                    .pipeline
                    .id_generator
                    .next_checkpoint_id()
                    .map_err(ApplicationError::IdGenerationFailed)?;
                let event_position = input.expected_version.checked_add(1).ok_or(
                    ApplicationError::VersionExhausted {
                        current: input.expected_version,
                        event_count: 1,
                    },
                )?;
                input.expected_version.checked_add(3).ok_or(
                    ApplicationError::VersionExhausted {
                        current: input.expected_version,
                        event_count: 3,
                    },
                )?;
                let body = LoopCheckpointBody {
                    schema_version: input.schema_version,
                    cycle_id: input.cycle_id,
                    attempt_id: input.attempt_id,
                    plan_revision_ref: input.plan_revision_ref,
                    context_manifest_ref: input.context_manifest_ref,
                    step_outcome_refs: input.step_outcome_refs,
                };
                Ok((
                    TaskRunCommand::CommitLoopCheckpoint {
                        checkpoint_id,
                        event_position,
                        body,
                        integrity_digest,
                    },
                    move |new_version| CommandOutcome::LoopCheckpointCommitted {
                        taskrun_id: input.taskrun_id,
                        checkpoint_id,
                        event_position,
                        new_version,
                    },
                ))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::CommandFingerprint;
    use crate::ports::*;
    use gocode_domain::event::Actor;
    use gocode_domain::id::{
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
            _: &gocode_domain::agent_loop::StepOutcomeRef,
            _: &gocode_domain::id::IntegrityDigest,
            _: &gocode_domain::reference::BudgetReservationRef,
            _: i64,
        ) -> Result<PreparedRetrySchedule, RetryScheduleError> {
            panic!("unexpected retry preparation")
        }
    }
    impl WakeEvidenceQueryPort for NoAuthorities {
        fn validate_current(
            &self,
            _: &gocode_domain::agent_loop::WakeEvidenceRef,
            _: TaskRunId,
            _: gocode_domain::id::CycleId,
            _: &gocode_domain::agent_loop::WakeCondition,
        ) -> Result<(), WakeEvidenceError> {
            panic!("unexpected wake validation")
        }
    }
    impl ReconciliationQueryPort for NoAuthorities {
        fn validate_current(
            &self,
            _: &gocode_domain::recovery::ReconciliationResultRef,
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
            _: &gocode_domain::verification::PlanEvaluationRef,
        ) -> Result<PlanEvaluation, VerificationQueryError> {
            panic!("unexpected verification lookup")
        }
    }

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
}
