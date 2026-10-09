use super::approval;
use super::capture::{self, PreparedCurrentCommand};
use super::supervise;
use super::*;
use runne_application::commands::CommandOutcome;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{
    AggregateScope, CommandCommit, EventStore, IdGenerator, IdempotencyScope, OperationTag,
};
use runne_domain::command::{TaskRunCommand, TerminalResult};
use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};
use runne_store::store::LocalCommandPermissionTerminalOutputV1;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) async fn execute_current_candidate(
    worker: &DaemonAutomaticTaskRuns,
    candidate: TaskRunQueueCandidate,
) -> Result<(), AutomaticTaskRunError> {
    let prepared = capture::prepare(worker, candidate)?;
    #[cfg(feature = "test-support")]
    super::super::diagnostic::stage("current_approval_wait");
    let receipt = match approval::admit(worker, &prepared).await {
        Ok(receipt) => receipt,
        Err(error @ AutomaticTaskRunError::RejectedBeforeEffect) => {
            #[cfg(feature = "test-support")]
            super::super::diagnostic::stage("current_approval_rejected");
            let stream = worker
                .store
                .load_task_run(prepared.identity.taskrun_id)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            let task =
                TaskRun::replay(&stream.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
            if stream.current_version == prepared.claimed_version
                && task.state() == TaskRunState::Running
                && task.active_attempt() == Some(&prepared.identity.attempt_id)
            {
                #[cfg(feature = "test-support")]
                super::super::diagnostic::stage("current_release_before");
                match worker
                    .release_before_effect(prepared.identity.clone(), stream.current_version)
                {
                    Ok(()) => {
                        #[cfg(feature = "test-support")]
                        super::super::diagnostic::stage("current_release_done");
                    }
                    Err(error) => {
                        #[cfg(feature = "test-support")]
                        super::super::diagnostic::stage("current_release_failed");
                        return Err(error);
                    }
                }
            } else {
                #[cfg(feature = "test-support")]
                super::super::diagnostic::stage("current_rejection_stale");
            }
            return Err(error);
        }
        Err(error) => {
            #[cfg(feature = "test-support")]
            super::super::diagnostic::stage("current_approval_other_error");
            return Err(error);
        }
    };
    let store = worker.store.clone();
    let roots = worker.root_admission.clone();
    let current_epoch = worker.current_epoch.clone();
    tokio::task::spawn_blocking(move || run_claimed(store, roots, current_epoch, prepared, receipt))
        .await
        .map_err(|_| AutomaticTaskRunError::Uncertain)?
}

fn run_claimed(
    store: StoreTransaction,
    roots: super::super::super::RootAdmissionGateway,
    current_epoch: Arc<AtomicU64>,
    prepared: PreparedCurrentCommand,
    receipt: runne_application::permission_modes::NativeScopeAdmissionReceipt,
) -> Result<(), AutomaticTaskRunError> {
    let identity = &prepared.identity;
    let binding = &prepared.binding;
    if current_epoch.load(Ordering::Acquire) != identity.node_epoch {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    let root = LinuxManagedAreaRoot::open_current_cgroup()
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let area_binding = ManagedAreaBinding::new(
        *identity.taskrun_id.as_bytes(),
        *identity.attempt_id.as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
    )
    .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let area = root
        .create_area(area_binding)
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    let bound = prepared
        .target
        .bind(binding.clone())
        .map_err(|_| AutomaticTaskRunError::RejectedBeforeEffect)?;
    let mut child = bound
        .spawn(&area, receipt, &[])
        .map_err(|_| AutomaticTaskRunError::Unavailable)?;
    if store
        .release_local_command_permission(
            identity,
            prepared.claimed_version,
            binding,
            &area,
            &mut child,
        )
        .is_err()
    {
        let _ = super::super::run::x2_supervisor::supervise_child(
            &mut child,
            &area,
            std::time::Duration::from_millis(5),
            |_| Ok(super::super::run::x2_supervisor::X2Observation::Stop),
        );
        return Err(AutomaticTaskRunError::Uncertain);
    }
    let terminal = supervise::supervise(
        &store,
        &roots,
        identity,
        binding,
        &area,
        &mut child,
        &current_epoch,
    )?;
    let latest = store
        .load_task_run(identity.taskrun_id)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let current_policy = supervise::current_policy(&roots, &store, binding);
    let policy_stop = terminal.stopped_for_policy || !current_policy;
    let payload = terminal_commit(
        &store,
        identity.taskrun_id,
        &latest,
        terminal.exit,
        policy_stop,
    )?;
    let output = LocalCommandPermissionTerminalOutputV1::new(
        terminal.stdout,
        terminal.stderr,
        terminal.stdout_observed,
        terminal.stderr_observed,
        terminal.stdout_truncated,
        terminal.stderr_truncated,
        true,
        true,
        false,
    )
    .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    store
        .commit_local_command_permission_terminal(payload, identity, binding, &child, output)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    drop(child);
    area.remove_empty()
        .map_err(|_| AutomaticTaskRunError::Uncertain)
}

fn terminal_commit(
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
