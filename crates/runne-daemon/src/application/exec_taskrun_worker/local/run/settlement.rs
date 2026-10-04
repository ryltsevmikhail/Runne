use super::super::super::*;
use runne_application::commands::CompleteTaskRunInput;
use runne_application::ports::EventStore;
use runne_domain::command::TerminalResult;
use runne_domain::id::TaskRunId;

pub(super) fn complete_local_task(
    taskruns: &SqliteTaskRunService,
    taskrun_id: TaskRunId,
    version: u64,
    exit_code: i32,
) -> Result<(), AutomaticTaskRunError> {
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
        .map_err(|_| AutomaticTaskRunError::Uncertain)
}

pub(super) fn complete_cancelled(
    taskruns: &SqliteTaskRunService,
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
    version: u64,
) -> Result<(), AutomaticTaskRunError> {
    let stream = store
        .load_task_run(taskrun_id)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    let current = runne_domain::task_run::TaskRun::replay(&stream.events)
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    if current.state() == runne_domain::task_run::TaskRunState::Cancelled {
        return Ok(());
    }
    if current.state() != runne_domain::task_run::TaskRunState::Cancelling
        || stream.current_version != version
    {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    taskruns
        .complete_claimed_taskrun_cancellation(
            &DaemonAutomaticTaskRuns::runtime_context(),
            runne_application::ports::CompleteClaimedTaskRunCancellationInput {
                taskrun_id,
                expected_version: version,
            },
            store,
        )
        .map(|_| ())
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    if super::test_barrier::pause_at(super::test_barrier::Point::AfterDurableTerminal).is_err() {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    Ok(())
}
