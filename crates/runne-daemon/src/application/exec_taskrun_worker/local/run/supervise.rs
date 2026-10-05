use super::super::*;
use super::settlement::{complete_cancelled, complete_local_task};
use super::x2_supervisor::{X2Observation, X2Outcome, supervise_gated_child};
use runne_application::ports::{
    TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunLeaseRenewal,
};
use runne_domain::id::CommandId;
use runne_domain::task_run::{TaskRun, TaskRunState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub(super) fn supervise(
    taskruns: Arc<SqliteTaskRunService>,
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    area: &runne_platform::process_managed_area::LinuxManagedArea,
    area_identity: &[u8],
    child: &mut runne_platform::local_command_linux::GatedLinuxChild<'_>,
    current_epoch: &AtomicU64,
) -> Result<(), AutomaticTaskRunError> {
    let mut renewal_at = std::time::Instant::now() + Duration::from_secs(30);
    let mut cancel_version = None;
    let observed = supervise_gated_child(child, area, Duration::from_millis(100), |child| {
        if std::time::Instant::now() >= renewal_at {
            if current_epoch.load(Ordering::Acquire) != identity.node_epoch
                || store
                    .renew_taskrun_assignment_lease(TaskRunLeaseRenewal {
                        identity: identity.clone(),
                        renewal_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
                        lease_duration_ms: 300_000,
                    })
                    .is_err()
            {
                return Err(());
            }
            renewal_at = std::time::Instant::now() + Duration::from_secs(30);
        }
        let stream = store.load_task_run(identity.taskrun_id).map_err(|_| ())?;
        let task = TaskRun::replay(&stream.events).map_err(|_| ())?;
        if task.state() == TaskRunState::Cancelling {
            store
                .request_local_command_stop(identity, area_identity)
                .map_err(|_| ())?;
            cancel_version = Some(stream.current_version);
            return Ok(X2Observation::Stop);
        }
        match child.try_wait() {
            Ok(Some(code)) => Ok(X2Observation::Complete(code)),
            Ok(None) => Ok(X2Observation::Continue),
            Err(_) => Err(()),
        }
    });
    let exit_code = match observed {
        Ok(X2Outcome::Stopped) => {
            let version =
                cancel_version.ok_or_else(|| mark_unconfirmed(store, identity, area_identity))?;
            confirm_stopped(store, identity, area, area_identity)
                .map_err(|_| mark_unconfirmed(store, identity, area_identity))?;
            complete_cancelled(&taskruns, store, identity.taskrun_id, version)?;
            return Ok(());
        }
        Ok(X2Outcome::Complete(code)) => code,
        Err(()) => return Err(mark_unconfirmed(store, identity, area_identity)),
    };
    let latest = store
        .load_task_run(identity.taskrun_id)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    if TaskRun::replay(&latest.events)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?
        .state()
        == TaskRunState::Cancelling
    {
        store
            .request_local_command_stop(identity, area_identity)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        confirm_stopped(store, identity, area, area_identity)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        complete_cancelled(
            &taskruns,
            store,
            identity.taskrun_id,
            latest.current_version,
        )?;
        return Ok(());
    }
    if record_exit(store, identity, area, area_identity, exit_code).is_err() {
        let current = store
            .load_task_run(identity.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if TaskRun::replay(&current.events)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?
            .state()
            == TaskRunState::Cancelling
        {
            store
                .request_local_command_stop(identity, area_identity)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            confirm_stopped(store, identity, area, area_identity)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            complete_cancelled(
                &taskruns,
                store,
                identity.taskrun_id,
                current.current_version,
            )?;
            return Ok(());
        }
        return Err(mark_unconfirmed(store, identity, area_identity));
    }
    if super::test_barrier::pause_at(super::test_barrier::Point::AfterExit).is_err() {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    let current = store
        .load_task_run(identity.taskrun_id)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    if complete_local_task(
        &taskruns,
        identity.taskrun_id,
        current.current_version,
        exit_code,
    )
    .is_err()
    {
        let latest = store
            .load_task_run(identity.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let latest_task =
            TaskRun::replay(&latest.events).map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if latest_task.state() == TaskRunState::Cancelling {
            store
                .request_local_command_stop(identity, area_identity)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            confirm_stopped(store, identity, area, area_identity)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
            complete_cancelled(
                &taskruns,
                store,
                identity.taskrun_id,
                latest.current_version,
            )?;
            return Ok(());
        }
        if !matches!(
            latest_task.state(),
            TaskRunState::Succeeded | TaskRunState::Failed
        ) {
            return Err(mark_unconfirmed(store, identity, area_identity));
        }
    }
    let terminal = store
        .load_task_run(identity.taskrun_id)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let event = terminal
        .last_event_id
        .ok_or(AutomaticTaskRunError::Uncertain)?;
    store
        .settle_local_command_terminal(
            identity,
            area_identity,
            event,
            terminal.current_version,
            area.prove_empty()
                .map_err(|_| AutomaticTaskRunError::Uncertain)?,
        )
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    if super::test_barrier::pause_at(super::test_barrier::Point::AfterDurableTerminal).is_err() {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    Ok(())
}

fn confirm_stopped(
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    area: &runne_platform::process_managed_area::LinuxManagedArea,
    area_identity: &[u8],
) -> Result<(), runne_application::ports::EventStoreError> {
    let proof = area
        .prove_empty()
        .map_err(|_| runne_application::ports::EventStoreError::CorruptData)?;
    store.confirm_local_command_stopped(identity, area_identity, proof)
}

fn record_exit(
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    area: &runne_platform::process_managed_area::LinuxManagedArea,
    area_identity: &[u8],
    exit_code: i32,
) -> Result<(), runne_application::ports::EventStoreError> {
    let proof = area
        .prove_empty()
        .map_err(|_| runne_application::ports::EventStoreError::CorruptData)?;
    store.record_local_command_exit(identity, area_identity, exit_code, proof)
}

pub(super) fn mark_unconfirmed(
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    area_identity: &[u8],
) -> AutomaticTaskRunError {
    match store.mark_local_command_stop_unconfirmed(identity, area_identity) {
        Ok(()) => AutomaticTaskRunError::Uncertain,
        Err(_) => AutomaticTaskRunError::Unavailable,
    }
}
