/// Cloneable canonical TaskRun host.
///
/// Commands always pass through [`RuntimeHandle`]. Queries reconstruct the
/// aggregate from the committed stream on Tokio's blocking executor.
#[derive(Clone)]
pub struct RuntimeTaskRunHost<E> {
    handle: RuntimeHandle,
    event_store: E,
}

impl<E> RuntimeTaskRunHost<E> {
    /// Creates a host from the runtime command handle and its authoritative
    /// event store.
    pub fn new(handle: RuntimeHandle, event_store: E) -> Self {
        Self {
            handle,
            event_store,
        }
    }
}

impl<E> TaskRunCommandHostPort for RuntimeTaskRunHost<E>
where
    E: EventStore + Clone + Send + Sync + 'static,
{
    async fn create_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CreateTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        let outcome = self
            .handle
            .create_task_run(
                into_application_context(context)?,
                CreateTaskRunInput {
                    conversation_id: command.conversation_id,
                    workspace_id: command.workspace_id,
                },
            )
            .await
            .map_err(map_runtime_error)?;

        match outcome {
            CommandOutcome::TaskRunCreated {
                taskrun_id,
                new_version,
            } => Ok(TaskRunCommandAck {
                taskrun_id,
                new_version,
                kind: TaskRunCommandAckKind::Created,
            }),
            _ => Err(TaskRunHostError::InvariantViolation),
        }
    }

    async fn queue_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        let outcome = self
            .handle
            .queue_task_run(
                into_application_context(context)?,
                QueueTaskRunInput {
                    taskrun_id: command.taskrun_id,
                    expected_version: command.expected_version,
                },
            )
            .await
            .map_err(map_runtime_error)?;

        match outcome {
            CommandOutcome::TaskRunQueued {
                taskrun_id,
                new_version,
            } => Ok(TaskRunCommandAck {
                taskrun_id,
                new_version,
                kind: TaskRunCommandAckKind::Queued,
            }),
            _ => Err(TaskRunHostError::InvariantViolation),
        }
    }

    async fn request_task_run_cancellation(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        let outcome = self
            .handle
            .cancel_task_run(
                into_application_context(context)?,
                CancelTaskRunInput {
                    taskrun_id: command.taskrun_id,
                    expected_version: command.expected_version,
                },
            )
            .await
            .map_err(map_runtime_error)?;

        match outcome {
            CommandOutcome::TaskRunCancellationRequested {
                taskrun_id,
                new_version,
            } => Ok(TaskRunCommandAck {
                taskrun_id,
                new_version,
                kind: TaskRunCommandAckKind::CancellationRequested,
            }),
            _ => Err(TaskRunHostError::InvariantViolation),
        }
    }

    async fn admit_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        let outcome = self
            .handle
            .admit_task_run(
                into_application_context(context)?,
                AdmitTaskRunInput {
                    taskrun_id: command.taskrun_id,
                    expected_version: command.expected_version,
                },
            )
            .await
            .map_err(map_runtime_error)?;

        match outcome {
            CommandOutcome::TaskRunAdmitted {
                taskrun_id,
                new_version,
            } => Ok(TaskRunCommandAck {
                taskrun_id,
                new_version,
                kind: TaskRunCommandAckKind::Admitted,
            }),
            _ => Err(TaskRunHostError::InvariantViolation),
        }
    }

    async fn start_attempt(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        let outcome = self
            .handle
            .start_attempt(
                into_application_context(context)?,
                StartAttemptInput {
                    taskrun_id: command.taskrun_id,
                    expected_version: command.expected_version,
                },
            )
            .await
            .map_err(map_runtime_error)?;

        match outcome {
            CommandOutcome::AttemptStarted {
                taskrun_id,
                attempt_id,
                new_version,
            } => Ok(TaskRunCommandAck {
                taskrun_id,
                new_version,
                kind: TaskRunCommandAckKind::AttemptStarted { attempt_id },
            }),
            _ => Err(TaskRunHostError::InvariantViolation),
        }
    }

    async fn complete_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CompleteTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        let canonical_result = command.result;
        let outcome = self
            .handle
            .complete_task_run(
                into_application_context(context)?,
                CompleteTaskRunInput {
                    taskrun_id: command.taskrun_id,
                    expected_version: command.expected_version,
                    result: terminal_result_to_domain(canonical_result.clone()),
                },
            )
            .await
            .map_err(map_runtime_error)?;

        match outcome {
            CommandOutcome::TaskRunCompleted {
                taskrun_id,
                new_version,
            } => Ok(TaskRunCommandAck {
                taskrun_id,
                new_version,
                kind: TaskRunCommandAckKind::Completed {
                    result: canonical_result,
                },
            }),
            _ => Err(TaskRunHostError::InvariantViolation),
        }
    }
}
