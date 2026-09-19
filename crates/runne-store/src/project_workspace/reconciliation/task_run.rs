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
        CommandReconciliationWitnessRef::SubmitTaskRun {
            conversation_id,
            workspace_id,
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
            CommandFingerprint::for_submit(&conversation_id, &workspace_id),
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
    let authoritative = outcome_for(witness, outcome)?;
    verify_committed_events(transaction, witness, &authoritative, context)?;
    Ok(Evidence::Terminal(Box::new(authoritative)))
}

/// Verifies the durable stream matches the exact committed batch: one
/// `CancellationRequested`, or the exact `Created + Queued` submit pair.
fn verify_committed_events(
    transaction: &Transaction<'_>,
    witness: &CommandReconciliationWitness,
    authoritative: &AuthoritativeCommandOutcome,
    context: &CommandReconciliationContext,
) -> Result<(), Error> {
    match witness.view() {
        CommandReconciliationWitnessRef::CancelTaskRun { task_run_id, .. } => verify_event(
            transaction,
            task_run_id,
            authoritative_version(authoritative)?,
            context,
        ),
        CommandReconciliationWitnessRef::SubmitTaskRun { .. } => {
            let Some(taskrun_id) = submitted_taskrun_id(&authoritative.view()) else {
                return Err(Error::InvariantViolation);
            };
            for (sequence, is_queued) in [(1_i64, false), (2_i64, true)] {
                let payload: Vec<u8> = transaction
                    .query_row(
                        "SELECT payload FROM events WHERE aggregate_type = 1 AND aggregate_id = ?1
                         AND sequence = ?2 AND command_id = ?3",
                        params![
                            taskrun_id.as_bytes(),
                            sequence,
                            context.command_id().as_bytes()
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| Error::InvariantViolation)?;
                let decoded = TaskRunEventCodec.decode(&payload);
                let matches_expected = match decoded {
                    Ok(TaskRunEvent::TaskRunCreated) => !is_queued,
                    Ok(TaskRunEvent::TaskRunQueued) => is_queued,
                    _ => false,
                };
                if !matches_expected {
                    return Err(Error::InvariantViolation);
                }
            }
            Ok(())
        }
        _ => Err(Error::InvariantViolation),
    }
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
mod tests {
    use super::*;
    use runne_domain::id::TaskRunId;

    const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000304";

    #[test]
    fn cancellation_receipt_correlates_to_the_expected_task_run_version() {
        let task_run: TaskRunId = TASK_RUN.parse().unwrap();
        let witness = CommandReconciliationWitness::cancel_task_run(task_run, 4);
        let outcome = outcome_for(
            &witness,
            CommandOutcome::TaskRunCancellationRequested {
                taskrun_id: task_run,
                new_version: 5,
            },
        )
        .unwrap();

        assert_eq!(
            outcome,
            AuthoritativeCommandOutcome::task_run_cancellation_requested(
                runne_api::TaskRunCommandAck {
                    taskrun_id: task_run,
                    new_version: 5,
                    kind: runne_api::TaskRunCommandAckKind::CancellationRequested,
                },
            )
        );
    }
}
