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
}
