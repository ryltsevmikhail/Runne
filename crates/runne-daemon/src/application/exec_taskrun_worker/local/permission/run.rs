use super::approval;
use super::capture::{self, PreparedCurrentCommand};
use super::supervise;
use super::*;
use runne_application::ports::EventStore;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaBinding};
use runne_store::store::LocalCommandPermissionTerminalOutputV1;
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
    // Test-support hook (legacy precedent local/run.rs): parks the worker
    // between the gated spawn and the GO so fault tests can fence the exact
    // release moment; an invalid barrier stops the unreleased child.
    if super::super::run::test_barrier::pause_at(
        super::super::run::test_barrier::Point::BeforeRelease,
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
        // A public cancellation that won the pre-release race is completed
        // durably here: the gated child was never released and the exact area
        // is proven empty (legacy parity: local/run.rs Cancelling branch).
        let stream = store
            .load_task_run(identity.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let task = TaskRun::replay(&stream.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if task.state() == TaskRunState::Cancelling {
            let empty = area
                .prove_empty()
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            store
                .complete_local_command_permission_cancelled_before_release(
                    identity, binding, empty,
                )
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            drop(child);
            area.remove_empty()
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            return Ok(());
        }
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
    let current_policy = super::policy_check::current_policy(&roots, &store, binding);
    let policy_stop = terminal.stopped_for_policy || !current_policy;
    let payload = super::terminal_commit::terminal_commit(
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
    // Test-support hook (legacy precedent run/supervise.rs): parks the worker
    // after the durable terminal settlement and before the area cleanup so
    // restart tests can SIGKILL the daemon with the receipt already stored.
    if super::super::run::test_barrier::pause_at(
        super::super::run::test_barrier::Point::AfterDurableTerminal,
    )
    .is_err()
    {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    drop(child);
    area.remove_empty()
        .map_err(|_| AutomaticTaskRunError::Uncertain)
}
