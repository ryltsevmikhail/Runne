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
        self.pipeline
            .execute_create(context, input.conversation_id, input.workspace_id, &fp)
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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
            &context.actor,
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

    // ══════════════════════════════════════════════════════════════════════════
    // Service-level authority port tests and helpers
    // ══════════════════════════════════════════════════════════════════════════

    use gocode_domain::agent_loop::{
        LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType, WakeCondition,
        WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource,
    };
    use gocode_domain::context::ContextManifestRef;
    use gocode_domain::event::{
        CommandContext, DomainEventDraft, EventEnvelope, Sensitivity, materialize_batch,
    };
    use gocode_domain::id::{AggregateId, CycleId, IntegrityDigest, PlanEvaluationId};
    use gocode_domain::plan::PlanRevisionRef;
    use gocode_domain::reference::{BudgetReservationRef, ResultRef};
    use gocode_domain::task_run::TaskRunEvent;
    use gocode_domain::timestamp::Timestamp;
    use gocode_domain::verification::{PlanEvaluationRef, PlanEvaluationResult};

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
}
