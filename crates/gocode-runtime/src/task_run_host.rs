//! Canonical TaskRun host backed by the runtime command path and event store.

use gocode_api::{
    CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand, CreateTaskRunCommand,
    ExistingTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext,
    TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::errors::ApplicationError;
use gocode_application::ports::{
    ApplicationCommandContext, EventStore, EventStoreError, PrincipalId,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::error::DomainError;
use gocode_domain::event::Actor;
use gocode_domain::task_run::{TaskRun, TaskRunState};

use crate::error::RuntimeError;
use crate::handle::RuntimeHandle;

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

impl<E> TaskRunQueryHostPort for RuntimeTaskRunHost<E>
where
    E: EventStore + Clone + Send + Sync + 'static,
{
    async fn get_task_run(
        &self,
        taskrun_id: gocode_domain::id::TaskRunId,
    ) -> Result<TaskRunSnapshot, TaskRunHostError> {
        let event_store = self.event_store.clone();
        tokio::task::spawn_blocking(move || {
            let stream = event_store
                .load_task_run(taskrun_id)
                .map_err(map_event_store_error)?;
            let last = stream.events.last().ok_or(TaskRunHostError::Unavailable)?;
            if last.sequence() != stream.current_version
                || Some(*last.event_id()) != stream.last_event_id
            {
                return Err(TaskRunHostError::Unavailable);
            }

            let aggregate =
                TaskRun::replay(&stream.events).map_err(|_| TaskRunHostError::Unavailable)?;
            Ok(TaskRunSnapshot {
                taskrun_id,
                state: state_to_canonical(aggregate.state()),
                stream_version: stream.current_version,
                active_attempt_id: aggregate.active_attempt().copied(),
                terminal_result: aggregate
                    .terminal_result()
                    .cloned()
                    .map(terminal_result_to_canonical),
            })
        })
        .await
        .map_err(|_| TaskRunHostError::Unavailable)?
    }
}

fn into_application_context(
    context: TaskRunCommandContext,
) -> Result<ApplicationCommandContext, TaskRunHostError> {
    let actor = Actor::new(context.actor.as_str().to_owned())
        .map_err(|_| TaskRunHostError::InvariantViolation)?;
    Ok(ApplicationCommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key,
        principal_id: PrincipalId(context.principal.as_str().to_owned()),
        actor,
    })
}

fn terminal_result_to_domain(result: CanonicalTerminalResult) -> TerminalResult {
    match result {
        CanonicalTerminalResult::Success => TerminalResult::Success,
        CanonicalTerminalResult::Failure { reason } => TerminalResult::Failure { reason },
    }
}

fn terminal_result_to_canonical(result: TerminalResult) -> CanonicalTerminalResult {
    match result {
        TerminalResult::Success => CanonicalTerminalResult::Success,
        TerminalResult::Failure { reason } => CanonicalTerminalResult::Failure { reason },
    }
}

fn state_to_canonical(state: TaskRunState) -> CanonicalTaskRunState {
    match state {
        TaskRunState::Created => CanonicalTaskRunState::Created,
        TaskRunState::Queued => CanonicalTaskRunState::Queued,
        TaskRunState::Admitted => CanonicalTaskRunState::Admitted,
        TaskRunState::Running => CanonicalTaskRunState::Running,
        TaskRunState::Waiting => CanonicalTaskRunState::Waiting,
        TaskRunState::Retrying => CanonicalTaskRunState::Retrying,
        TaskRunState::Checkpointing => CanonicalTaskRunState::Checkpointing,
        TaskRunState::Cancelling => CanonicalTaskRunState::Cancelling,
        TaskRunState::Reconciling => CanonicalTaskRunState::Reconciling,
        TaskRunState::Succeeded => CanonicalTaskRunState::Succeeded,
        TaskRunState::Failed => CanonicalTaskRunState::Failed,
        TaskRunState::Cancelled => CanonicalTaskRunState::Cancelled,
        TaskRunState::BudgetExhausted => CanonicalTaskRunState::BudgetExhausted,
        TaskRunState::PolicyDenied => CanonicalTaskRunState::PolicyDenied,
        TaskRunState::Unrecoverable => CanonicalTaskRunState::Unrecoverable,
    }
}

fn map_runtime_error(error: RuntimeError) -> TaskRunHostError {
    match error {
        RuntimeError::Backpressure { .. } => TaskRunHostError::Backpressure,
        RuntimeError::RuntimeClosed | RuntimeError::WorkerExecutionFailed { .. } => {
            TaskRunHostError::Unavailable
        }
        RuntimeError::Application(error) => map_application_error(error),
        RuntimeError::ConversationApplication(_) => TaskRunHostError::InvariantViolation,
    }
}

fn map_application_error(error: ApplicationError) -> TaskRunHostError {
    match error {
        ApplicationError::AggregateNotFound { .. }
        | ApplicationError::EventStoreFailed(EventStoreError::NotFound) => {
            TaskRunHostError::NotFound
        }
        ApplicationError::VersionConflict { .. }
        | ApplicationError::IdempotencyConflict { .. }
        | ApplicationError::InvalidCommandFingerprint(_)
        | ApplicationError::Domain(DomainError::InvalidTransition { .. })
        | ApplicationError::Domain(DomainError::TerminalImmutable { .. }) => {
            TaskRunHostError::Conflict
        }
        ApplicationError::EventStoreFailed(_)
        | ApplicationError::StorageFailed(_)
        | ApplicationError::IdGenerationFailed(_)
        | ApplicationError::TimePortFailed(_)
        | ApplicationError::RetryScheduleRejected(_)
        | ApplicationError::WakeEvidenceRejected(_)
        | ApplicationError::ReconciliationRejected(_)
        | ApplicationError::VerificationRejected(_) => TaskRunHostError::Unavailable,
        ApplicationError::VersionExhausted { .. }
        | ApplicationError::Domain(_)
        | ApplicationError::StreamConsistencyViolation(_)
        | ApplicationError::CommitVersionMismatch { .. }
        | ApplicationError::InvalidAuthorityResult => TaskRunHostError::InvariantViolation,
    }
}

fn map_event_store_error(error: EventStoreError) -> TaskRunHostError {
    match error {
        EventStoreError::NotFound => TaskRunHostError::NotFound,
        EventStoreError::CorruptData | EventStoreError::Unavailable => {
            TaskRunHostError::Unavailable
        }
    }
}
