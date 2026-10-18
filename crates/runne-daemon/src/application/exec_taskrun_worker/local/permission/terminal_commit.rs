use super::*;
use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, CommandCommit, IdGenerator, IdempotencyScope, OperationTag,
};
use runne_domain::command::{TaskRunCommand, TerminalResult};
use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use runne_store::store::StoreTransaction;
use sha2::{Digest, Sha256};

pub(super) fn terminal_commit(
    store: &StoreTransaction,
    taskrun_id: runne_domain::id::TaskRunId,
    stream: &runne_application::ports::LoadedStream,
    exit: LinuxLeaderExitKindV1,
    policy_stop: bool,
) -> Result<CommandCommit, AutomaticTaskRunError> {
    let task = TaskRun::replay(&stream.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let context = DaemonAutomaticTaskRuns::runtime_context();
    let (command, fingerprint, operation, outcome) = match task.state() {
        TaskRunState::Cancelling => {
            let mut hash = Sha256::new();
            hash.update(b"runne-taskrun-claimed-cancellation-complete-v1");
            hash.update(taskrun_id.as_bytes());
            hash.update(stream.current_version.to_be_bytes());
            (
                TaskRunCommand::CompleteCancellation,
                CommandFingerprint::from_bytes(hash.finalize().into()),
                OperationTag::CompleteQueuedCancellation,
                CommandOutcome::TaskRunCancellationCompleted {
                    taskrun_id,
                    new_version: stream
                        .current_version
                        .checked_add(1)
                        .ok_or(AutomaticTaskRunError::Uncertain)?,
                },
            )
        }
        TaskRunState::Running => {
            let (command, result) = running_completion(exit, policy_stop);
            let fingerprint =
                CommandFingerprint::for_complete(&taskrun_id, &result, stream.current_version)
                    .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            (
                command,
                fingerprint,
                OperationTag::Complete,
                CommandOutcome::TaskRunCompleted {
                    taskrun_id,
                    new_version: stream
                        .current_version
                        .checked_add(1)
                        .ok_or(AutomaticTaskRunError::Uncertain)?,
                },
            )
        }
        _ => return Err(AutomaticTaskRunError::Uncertain),
    };
    let drafts = task
        .decide(command)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let ids = store
        .next_event_ids(drafts.len())
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let domain_context = CommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        actor: context.actor.clone(),
    };
    let events = materialize_batch(drafts, &ids, stream.last_event_id, &domain_context)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    Ok(CommandCommit {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key,
        idempotency_scope: IdempotencyScope {
            runtime_authority_id: store.runtime_authority_id().clone(),
            principal_id: context.principal_id,
            operation,
            aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
        },
        command_fingerprint: fingerprint,
        expected_version: stream.current_version,
        events,
        command_result: outcome,
    })
}

pub(super) fn running_completion(
    exit: LinuxLeaderExitKindV1,
    policy_stop: bool,
) -> (TaskRunCommand, TerminalResult) {
    match exit {
        LinuxLeaderExitKindV1::Exited { code: 0 } if !policy_stop => (
            TaskRunCommand::Complete {
                result: TerminalResult::Success,
            },
            TerminalResult::Success,
        ),
        LinuxLeaderExitKindV1::Exited { code } if !policy_stop => {
            let reason = format!("local_command_exit_{code}");
            (
                TaskRunCommand::Complete {
                    result: TerminalResult::Failure {
                        reason: reason.clone(),
                    },
                },
                TerminalResult::Failure { reason },
            )
        }
        LinuxLeaderExitKindV1::Signaled { signal, .. } if !policy_stop => {
            let reason = format!("local_command_signal_v1_{signal}");
            (
                TaskRunCommand::Fail {
                    reason: reason.clone(),
                },
                TerminalResult::Failure { reason },
            )
        }
        _ => {
            let reason = "local_command_policy_stopped_v1".to_owned();
            (
                TaskRunCommand::Fail {
                    reason: reason.clone(),
                },
                TerminalResult::Failure { reason },
            )
        }
    }
}
