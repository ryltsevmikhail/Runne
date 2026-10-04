use runne_api::{
    AuthoritativeCommandOutcome, CommandReconciliationContext, CommandReconciliationWitness,
    CommandReconciliationWitnessRef, TaskRunCommandAck, TaskRunCommandAckKind,
};
use runne_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepositoryError as Error,
};
use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{AggregateScope, IdempotencyScope, OperationTag};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::codec::{CommandOutcomeCodec, IdempotencyScopeCodec, StoreCodec, TaskRunEventCodec};
use runne_domain::task_run::TaskRunEvent;

mod verify;

pub(super) fn lookup(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    let principal = runne_application::ports::PrincipalId(context.principal().as_str().into());
    let (expected_scope, fingerprint) = match witness.view() {
        CommandReconciliationWitnessRef::CancelTaskRun {
            task_run_id,
            expected_version,
        } => (
            IdempotencyScope {
                runtime_authority_id: store.runtime_authority_id().clone(),
                principal_id: principal,
                operation: OperationTag::CancelTaskRun,
                aggregate_scope: AggregateScope::ExistingTaskRun {
                    taskrun_id: task_run_id,
                },
            },
            CommandFingerprint::for_cancel(&task_run_id, expected_version),
        ),
        CommandReconciliationWitnessRef::SupersedeUnknownTaskRun {
            predecessor_taskrun_id,
            expected_version,
        } => {
            let input = runne_application::commands::SupersedeUnknownTaskRunInput {
                predecessor_taskrun_id,
                expected_predecessor_version: expected_version,
                acknowledgment: runne_application::commands::UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1,
            };
            (
                IdempotencyScope {
                    runtime_authority_id: store.runtime_authority_id().clone(),
                    principal_id: principal,
                    operation: OperationTag::SupersedeUnknownTaskRun,
                    aggregate_scope: AggregateScope::ExistingTaskRun {
                        taskrun_id: predecessor_taskrun_id,
                    },
                },
                CommandFingerprint::for_supersede_unknown_task_run(&input),
            )
        }
        CommandReconciliationWitnessRef::SubmitTaskRun {
            conversation_id,
            workspace_id,
            input,
        } => (
            IdempotencyScope {
                runtime_authority_id: store.runtime_authority_id().clone(),
                principal_id: principal,
                operation: OperationTag::SubmitTaskRun,
                aggregate_scope: AggregateScope::NewTaskRun {
                    conversation_id,
                    workspace_id,
                },
            },
            match input {
                Some(input) => {
                    CommandFingerprint::for_submit(&conversation_id, &workspace_id, input)
                }
                None => CommandFingerprint::for_submit_legacy(&conversation_id, &workspace_id),
            },
        ),
        _ => return Err(Error::InvariantViolation),
    };
    let expected_scope_bytes = IdempotencyScopeCodec
        .encode(&expected_scope)
        .map_err(|_| Error::InvariantViolation)?;
    let stored = transaction
        .query_row(
            "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
             FROM command_receipts WHERE command_id = ?1",
            [context.command_id().as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    let Some((scope, key, stored_fingerprint, outcome)) = stored else {
        return scoped_collision_or_not_committed(
            transaction,
            &expected_scope_bytes,
            context.idempotency_key().as_str().as_bytes(),
            context.command_id().as_bytes(),
        );
    };
    let decoded_scope = IdempotencyScopeCodec
        .decode(&scope)
        .map_err(|_| Error::InvariantViolation)?;
    if decoded_scope != expected_scope
        || scope != expected_scope_bytes
        || key != context.idempotency_key().as_str().as_bytes()
        || stored_fingerprint != fingerprint.as_bytes()
    {
        return Err(Error::Conflict);
    }
    let outcome = CommandOutcomeCodec
        .decode(&outcome)
        .map_err(|_| Error::InvariantViolation)?;
    let authoritative = outcome_for(Some(transaction), witness, outcome)?;
    verify::verify_committed_events(transaction, witness, &authoritative, context)?;
    Ok(Evidence::Terminal(Box::new(authoritative)))
}

fn scoped_collision_or_not_committed(
    transaction: &Transaction<'_>,
    scope: &[u8],
    key: &[u8],
    command_id: &[u8],
) -> Result<Evidence, Error> {
    let collision: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM command_receipts
             WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2)
             OR EXISTS(SELECT 1 FROM project_workspace_command_receipts
             WHERE command_id = ?3)",
            params![scope, key, command_id],
            |row| row.get(0),
        )
        .map_err(|_| Error::Unavailable)?;
    if collision {
        Err(Error::Conflict)
    } else {
        Ok(Evidence::NotCommitted)
    }
}

fn verify_event(
    transaction: &Transaction<'_>,
    task_run_id: runne_domain::id::TaskRunId,
    version: u64,
    context: &CommandReconciliationContext,
) -> Result<(), Error> {
    let payload: Vec<u8> = transaction
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1
             AND sequence = ?2 AND command_id = ?3",
            params![
                task_run_id.as_bytes(),
                i64::try_from(version).map_err(|_| Error::InvariantViolation)?,
                context.command_id().as_bytes()
            ],
            |row| row.get(0),
        )
        .map_err(|_| Error::InvariantViolation)?;
    if matches!(
        TaskRunEventCodec.decode(&payload),
        Ok(TaskRunEvent::CancellationRequested)
    ) {
        Ok(())
    } else {
        Err(Error::InvariantViolation)
    }
}

pub(super) fn outcome_for(
    transaction: Option<&Transaction<'_>>,
    witness: &CommandReconciliationWitness,
    outcome: CommandOutcome,
) -> Result<AuthoritativeCommandOutcome, Error> {
    match witness.view() {
        CommandReconciliationWitnessRef::CancelTaskRun {
            task_run_id,
            expected_version,
        } => {
            let CommandOutcome::TaskRunCancellationRequested {
                taskrun_id: stored_task_run_id,
                new_version,
            } = outcome
            else {
                return Err(Error::InvariantViolation);
            };
            if stored_task_run_id != task_run_id
                || expected_version.checked_add(1) != Some(new_version)
            {
                return Err(Error::InvariantViolation);
            }
            Ok(
                AuthoritativeCommandOutcome::task_run_cancellation_requested(TaskRunCommandAck {
                    taskrun_id: stored_task_run_id,
                    new_version,
                    kind: TaskRunCommandAckKind::CancellationRequested,
                }),
            )
        }
        CommandReconciliationWitnessRef::SubmitTaskRun { .. } => {
            let CommandOutcome::TaskRunSubmitted {
                taskrun_id: stored_task_run_id,
                new_version,
            } = outcome
            else {
                return Err(Error::InvariantViolation);
            };
            if new_version != 2 {
                return Err(Error::InvariantViolation);
            }
            Ok(AuthoritativeCommandOutcome::task_run_submitted(
                TaskRunCommandAck {
                    taskrun_id: stored_task_run_id,
                    new_version,
                    kind: TaskRunCommandAckKind::Submitted,
                },
            ))
        }
        CommandReconciliationWitnessRef::SupersedeUnknownTaskRun {
            predecessor_taskrun_id,
            expected_version,
        } => {
            let CommandOutcome::UnknownSuccessorCreated {
                predecessor_taskrun_id: actual_predecessor,
                predecessor_version,
                successor_taskrun_id,
                successor_version,
                ..
            } = outcome
            else {
                return Err(Error::InvariantViolation);
            };
            if actual_predecessor != predecessor_taskrun_id
                || expected_version.checked_add(1) != Some(predecessor_version)
                || successor_taskrun_id == predecessor_taskrun_id
                || successor_version != 2
            {
                return Err(Error::InvariantViolation);
            }
            let origin =
                crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
                    transaction.ok_or(Error::InvariantViolation)?,
                    successor_taskrun_id,
                )
                .map_err(|_| Error::InvariantViolation)?;
            if origin.is_none() {
                return Err(Error::InvariantViolation);
            }
            Ok(AuthoritativeCommandOutcome::unknown_successor_created(
                TaskRunCommandAck {
                    taskrun_id: successor_taskrun_id,
                    new_version: successor_version,
                    kind: runne_api::TaskRunCommandAckKind::UnknownSuccessorCreated {
                        predecessor_taskrun_id,
                        predecessor_version,
                        successor_taskrun_id,
                        successor_version,
                    },
                },
            ))
        }
        _ => Err(Error::InvariantViolation),
    }
}

fn authoritative_version(outcome: &AuthoritativeCommandOutcome) -> Result<u64, Error> {
    match outcome.view() {
        runne_api::AuthoritativeCommandOutcomeRef::TaskRunCancellationRequested(ack) => {
            Ok(ack.new_version)
        }
        _ => Err(Error::InvariantViolation),
    }
}

fn submitted_taskrun_id(
    outcome: &runne_api::AuthoritativeCommandOutcomeRef<'_>,
) -> Option<runne_domain::id::TaskRunId> {
    match outcome {
        runne_api::AuthoritativeCommandOutcomeRef::TaskRunSubmitted(ack) => Some(ack.taskrun_id),
        _ => None,
    }
}

#[cfg(test)]
#[path = "task_run_tests.rs"]
mod tests;
