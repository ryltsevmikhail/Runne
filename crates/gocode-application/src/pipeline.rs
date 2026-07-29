//! Execution pipeline — internal engine for command processing.
//!
//! Not public API. [`crate::service::TaskRunService`] is the only
//! public entry point.

use gocode_domain::command::{CreateTaskRun, TaskRunCommand};
use gocode_domain::event::{Actor, CommandContext, materialize_batch};
use gocode_domain::id::{CommandId, IdempotencyKey, TaskRunId};
use gocode_domain::task_run::TaskRun;

use crate::commands::CommandOutcome;
use crate::errors::{ApplicationError, StreamConsistencyViolation};
use crate::fingerprint::CommandFingerprint;
use crate::ports::{
    ApplicationCommandContext, CommandCommit, CommitResult, EventStore, IdGenerator,
    IdempotencyScope, LoadedStream, ReceiptLookup, UnitOfWork,
};

pub(crate) struct Pipeline<E, U, I> {
    pub event_store: E,
    pub unit_of_work: U,
    pub id_generator: I,
    pub runtime_authority_id: crate::ports::RuntimeAuthorityId,
}

impl<E: EventStore, U: UnitOfWork, I: IdGenerator> Pipeline<E, U, I> {
    pub(crate) fn execute_create(
        &self,
        context: &ApplicationCommandContext,
        conversation_id: gocode_domain::id::ConversationId,
        workspace_id: gocode_domain::id::WorkspaceId,
        fingerprint: &CommandFingerprint,
    ) -> Result<CommandOutcome, ApplicationError> {
        let taskrun_id = self
            .id_generator
            .next_taskrun_id()
            .map_err(ApplicationError::IdGenerationFailed)?;

        let scope = IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: crate::ports::OperationTag::CreateTaskRun,
            aggregate_scope: crate::ports::AggregateScope::NewTaskRun {
                conversation_id,
                workspace_id,
            },
        };

        let lookup = self
            .unit_of_work
            .lookup_receipt(
                context.command_id,
                &context.idempotency_key,
                &scope,
                fingerprint,
            )
            .map_err(ApplicationError::from)?;
        if let ReceiptLookup::Duplicate { stored_result } = lookup {
            return Ok(stored_result);
        }

        let cmd = CreateTaskRun {
            taskrun_id,
            conversation_id,
            workspace_id,
        };

        let domain_ctx = CommandContext {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            actor: context.actor.clone(),
        };

        let draft = TaskRun::decide_create(cmd).map_err(ApplicationError::Domain)?;

        let event_ids = self
            .id_generator
            .next_event_ids(1)
            .map_err(ApplicationError::IdGenerationFailed)?;

        let uncommitted =
            materialize_batch(vec![draft], &event_ids, None, &domain_ctx).map_err(|_e| {
                ApplicationError::StorageFailed(crate::ports::StorageFailureKind::CorruptData)
            })?;

        let new_version = 1u64;
        let outcome = CommandOutcome::TaskRunCreated {
            taskrun_id,
            new_version,
        };

        let commit_payload = CommandCommit {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint: *fingerprint,
            expected_version: 0,
            events: uncommitted,
            command_result: outcome.clone(),
        };

        match self
            .unit_of_work
            .commit(commit_payload)
            .map_err(ApplicationError::from)?
        {
            CommitResult::Committed { new_version: v } => {
                if v != new_version {
                    return Err(ApplicationError::CommitVersionMismatch {
                        computed: new_version,
                        returned: v,
                    });
                }
                Ok(outcome)
            }
            CommitResult::Duplicate { stored_result } => Ok(stored_result),
        }
    }

    // Spec requires each argument as an explicit pipeline parameter;
    // grouping into a struct would create an artificial single-use type.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_existing(
        #[allow(clippy::too_many_arguments)] &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        principal_id: &crate::ports::PrincipalId,
        actor: &Actor,
        taskrun_id: TaskRunId,
        expected_version: u64,
        domain_command: TaskRunCommand,
        fingerprint: &CommandFingerprint,
        outcome_builder: impl FnOnce(u64) -> CommandOutcome,
        operation: crate::ports::OperationTag,
    ) -> Result<CommandOutcome, ApplicationError> {
        self.execute_existing_prepared(
            command_id,
            idempotency_key,
            principal_id,
            actor,
            taskrun_id,
            expected_version,
            fingerprint,
            operation,
            |_| Ok((domain_command, outcome_builder)),
        )
    }

    /// Execute an existing-aggregate command whose authoritative/generated
    /// values must only be prepared after duplicate receipt lookup and exact
    /// stream replay.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_existing_prepared<B>(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
        principal_id: &crate::ports::PrincipalId,
        actor: &Actor,
        taskrun_id: TaskRunId,
        expected_version: u64,
        fingerprint: &CommandFingerprint,
        operation: crate::ports::OperationTag,
        prepare: impl FnOnce(&TaskRun) -> Result<(TaskRunCommand, B), ApplicationError>,
    ) -> Result<CommandOutcome, ApplicationError>
    where
        B: FnOnce(u64) -> CommandOutcome,
    {
        let scope = IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: principal_id.clone(),
            operation,
            aggregate_scope: crate::ports::AggregateScope::ExistingTaskRun { taskrun_id },
        };

        let lookup = self
            .unit_of_work
            .lookup_receipt(command_id, idempotency_key, &scope, fingerprint)
            .map_err(ApplicationError::from)?;
        if let ReceiptLookup::Duplicate { stored_result } = lookup {
            return Ok(stored_result);
        }

        let stream = self
            .event_store
            .load_task_run(taskrun_id)
            .map_err(ApplicationError::EventStoreFailed)?;

        validate_stream(&stream).map_err(ApplicationError::StreamConsistencyViolation)?;

        let current_version = stream.current_version;
        let last_event_id = stream.last_event_id;

        let domain_ctx = CommandContext {
            command_id,
            idempotency_key: idempotency_key.clone(),
            actor: actor.clone(),
        };

        let agg = if stream.events.is_empty() {
            return Err(ApplicationError::AggregateNotFound { taskrun_id });
        } else {
            TaskRun::replay(&stream.events).map_err(ApplicationError::Domain)?
        };

        if current_version != expected_version {
            return Err(ApplicationError::VersionConflict {
                expected: expected_version,
                actual: current_version,
            });
        }

        let (domain_command, outcome_builder) = prepare(&agg)?;

        let drafts = agg
            .decide(domain_command)
            .map_err(ApplicationError::Domain)?;
        let event_count = drafts.len();

        let event_ids = self
            .id_generator
            .next_event_ids(event_count)
            .map_err(ApplicationError::IdGenerationFailed)?;

        let uncommitted = materialize_batch(drafts, &event_ids, last_event_id, &domain_ctx)
            .map_err(|_| {
                ApplicationError::StorageFailed(crate::ports::StorageFailureKind::CorruptData)
            })?;

        let new_version = current_version.checked_add(event_count as u64).ok_or(
            ApplicationError::VersionExhausted {
                current: current_version,
                event_count,
            },
        )?;

        let outcome = outcome_builder(new_version);

        let commit_payload = CommandCommit {
            command_id,
            idempotency_key: idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint: *fingerprint,
            expected_version,
            events: uncommitted,
            command_result: outcome.clone(),
        };

        match self
            .unit_of_work
            .commit(commit_payload)
            .map_err(ApplicationError::from)?
        {
            CommitResult::Committed { new_version: v } => {
                if v != new_version {
                    return Err(ApplicationError::CommitVersionMismatch {
                        computed: new_version,
                        returned: v,
                    });
                }
                Ok(outcome)
            }
            CommitResult::Duplicate { stored_result } => Ok(stored_result),
        }
    }
}

fn validate_stream(stream: &LoadedStream) -> Result<(), StreamConsistencyViolation> {
    if stream.events.is_empty() {
        if stream.current_version != 0 {
            return Err(StreamConsistencyViolation::EmptyWithNonZeroVersion {
                current_version: stream.current_version,
            });
        }
        if stream.last_event_id.is_some() {
            return Err(StreamConsistencyViolation::NonEmptyWithMissingLastId);
        }
        return Ok(());
    }

    if stream.current_version == 0 {
        return Err(StreamConsistencyViolation::NonEmptyWithZeroVersion);
    }

    let last = stream.events.last().unwrap();
    if Some(*last.event_id()) != stream.last_event_id {
        return Err(StreamConsistencyViolation::LastEventIdMismatch);
    }

    if last.sequence() != stream.current_version {
        return Err(StreamConsistencyViolation::SequenceMismatch {
            index: stream.events.len() - 1,
            expected: stream.current_version,
            actual: last.sequence(),
        });
    }

    Ok(())
}
