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

    pub fn cancel_task_run(
        &self,
        context: &ApplicationCommandContext,
        input: CancelTaskRunInput,
    ) -> Result<CommandOutcome, ApplicationError> {
        let fp = CommandFingerprint::for_cancel(&input.taskrun_id, input.expected_version);
        self.pipeline.execute_existing(
            context.command_id,
            &context.idempotency_key,
            &context.principal_id,
            &context.actor,
            input.taskrun_id,
            input.expected_version,
            TaskRunCommand::RequestCancellation,
            &fp,
            |new_version| CommandOutcome::TaskRunCancellationRequested {
                taskrun_id: input.taskrun_id,
                new_version,
            },
            OperationTag::CancelTaskRun,
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
