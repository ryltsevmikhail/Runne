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
