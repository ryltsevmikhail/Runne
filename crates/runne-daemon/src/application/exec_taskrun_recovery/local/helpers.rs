use super::super::super::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use super::super::super::{SqliteTaskRunService, StoreTransaction};
use runne_application::commands::CompleteTaskRunInput;
use runne_application::ports::{CompleteClaimedTaskRunCancellationInput, EventStore};
use runne_domain::command::TerminalResult;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::process_managed_area::{
    LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding, ManagedAreaIdentity,
};
use runne_store::store::LocalCommandRecoveryCandidate;

pub(super) fn each_recovery_candidate<T, E>(
    candidates: &[T],
    mut renew: impl FnMut() -> Result<(), E>,
    mut recover: impl FnMut(&T) -> Result<(), E>,
) -> Result<(), E> {
    for candidate in candidates {
        renew()?;
        recover(candidate)?;
        renew()?;
    }
    Ok(())
}

pub(super) fn reopen_exact_area(
    root: &LinuxManagedAreaRoot,
    candidate: &LocalCommandRecoveryCandidate,
) -> Result<LinuxManagedArea, ()> {
    let identity = ManagedAreaIdentity::from_bytes(&candidate.area_identity).map_err(|_| ())?;
    let bytes = identity.to_bytes();
    if bytes[52..68] != *candidate.identity.taskrun_id.as_bytes()
        || bytes[68..84] != *candidate.identity.attempt_id.as_bytes()
    {
        return Err(());
    }
    let binding = ManagedAreaBinding::new(
        *candidate.identity.taskrun_id.as_bytes(),
        *candidate.identity.attempt_id.as_bytes(),
        bytes[84..100].try_into().map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    root.reopen_area(identity, binding).map_err(|_| ())
}

pub(super) fn complete_cancelled(
    taskruns: &SqliteTaskRunService,
    store: &StoreTransaction,
    candidate: &LocalCommandRecoveryCandidate,
    version: u64,
) -> Result<(), ()> {
    let stream = store
        .load_task_run(candidate.identity.taskrun_id)
        .map_err(|_| ())?;
    if TaskRun::replay(&stream.events).map_err(|_| ())?.state() == TaskRunState::Cancelled {
        return Ok(());
    }
    if stream.current_version != version {
        return Err(());
    }
    taskruns
        .complete_claimed_taskrun_cancellation(
            &DaemonAutomaticTaskRuns::runtime_context(),
            CompleteClaimedTaskRunCancellationInput {
                taskrun_id: candidate.identity.taskrun_id,
                expected_version: version,
            },
            store,
        )
        .map(|_| ())
        .map_err(|_| ())
}

pub(super) fn complete_local_task(
    taskruns: &SqliteTaskRunService,
    taskrun_id: runne_domain::id::TaskRunId,
    version: u64,
    exit_code: i32,
) -> Result<(), ()> {
    let result = if exit_code == 0 {
        TerminalResult::Success
    } else {
        TerminalResult::Failure {
            reason: format!("local_command_exit_{exit_code}"),
        }
    };
    taskruns
        .complete_task_run(
            &DaemonAutomaticTaskRuns::runtime_context(),
            CompleteTaskRunInput {
                taskrun_id,
                result,
                expected_version: version,
            },
        )
        .map(|_| ())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::each_recovery_candidate;

    #[test]
    fn recovery_renews_between_candidates_before_bounded_lease_expires() {
        use std::cell::Cell;

        let candidates = [0, 1, 2];
        let elapsed = Cell::new(0_u64);
        let expiry = Cell::new(0_u64);
        let renewals = Cell::new(0_u8);
        each_recovery_candidate(
            &candidates,
            || {
                renewals.set(renewals.get() + 1);
                expiry.set(elapsed.get() + 30);
                Ok::<_, ()>(())
            },
            |_| {
                assert!(
                    elapsed.get() < expiry.get(),
                    "recovery lease must be current"
                );
                elapsed.set(elapsed.get() + 20);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(renewals.get(), 6);
        assert_eq!(elapsed.get(), 60);
    }
}
