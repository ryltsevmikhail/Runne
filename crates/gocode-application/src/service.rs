//! Public application facade — the only entry point for callers.
//!
//! [`TaskRunService`] owns the pipeline and exposes five typed use cases.

use gocode_domain::command::{TaskRunCommand, TerminalResult};
use gocode_domain::id::{AttemptId, TaskRunId};

use crate::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use crate::errors::ApplicationError;
use crate::fingerprint::CommandFingerprint;
use crate::pipeline::Pipeline;
use crate::ports::{
    ApplicationCommandContext, EventStore, IdGenerator, OperationTag, PrincipalId,
    RuntimeAuthorityId, UnitOfWork,
};

pub struct TaskRunService<E, U, I> {
    pipeline: Pipeline<E, U, I>,
}

impl<E: EventStore, U: UnitOfWork, I: IdGenerator> TaskRunService<E, U, I> {
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
        }
    }

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
