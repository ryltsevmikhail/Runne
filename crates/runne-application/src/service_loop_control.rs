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
}
