use super::*;
use runne_application::ports::TaskRunQueueCandidate;
use runne_store::store::LocalCommandPermissionRoute;

#[path = "permission/approval.rs"]
mod approval;
#[path = "permission/capture.rs"]
mod capture;
#[path = "permission/policy_check.rs"]
mod policy_check;
#[path = "permission/run.rs"]
mod run;
#[path = "permission/supervise.rs"]
mod supervise;
#[path = "permission/terminal_commit.rs"]
mod terminal_commit;
#[cfg(test)]
#[path = "permission/tests.rs"]
mod tests;

pub(super) async fn execute_candidate(
    worker: &DaemonAutomaticTaskRuns,
    candidate: TaskRunQueueCandidate,
) -> Option<Result<(), AutomaticTaskRunError>> {
    let stream = match worker.store.load_task_run(candidate.taskrun_id) {
        Ok(stream) if stream.current_version == candidate.current_version => stream,
        Ok(_) => return Some(Err(AutomaticTaskRunError::Unavailable)),
        Err(_) => return Some(Err(AutomaticTaskRunError::Uncertain)),
    };
    let task = match TaskRun::replay(&stream.events) {
        Ok(task) => task,
        Err(_) => return Some(Err(AutomaticTaskRunError::Uncertain)),
    };
    task.snapshot_v1()
        .input()
        .and_then(|input| input.local_command())?;
    match worker
        .store
        .local_command_permission_route(candidate.taskrun_id)
    {
        Ok(LocalCommandPermissionRoute::LegacyBound) => legacy_candidate(worker, candidate).await,
        Ok(LocalCommandPermissionRoute::LegacyTerminal) => {
            Some(Err(AutomaticTaskRunError::Unavailable))
        }
        Ok(LocalCommandPermissionRoute::CurrentPermission) => {
            Some(run::execute_current_candidate(worker, candidate).await)
        }
        Err(_) => Some(Err(AutomaticTaskRunError::Uncertain)),
    }
}

async fn legacy_candidate(
    worker: &DaemonAutomaticTaskRuns,
    candidate: TaskRunQueueCandidate,
) -> Option<Result<(), AutomaticTaskRunError>> {
    match worker.prepare_local_candidate(candidate) {
        Ok(None) => None,
        Err(AutomaticTaskRunError::RejectedBeforeEffect) => {
            Some(worker.fail_rejected_local_command(candidate))
        }
        Err(error) => Some(Err(error)),
        Ok(Some((workspace_id, command, prepared, principal))) => {
            let decision = match worker
                .resolve_local_approval(
                    candidate.taskrun_id,
                    workspace_id,
                    &command,
                    &prepared,
                    principal.clone(),
                )
                .await
            {
                Ok(value) => value,
                Err(AutomaticTaskRunError::RejectedBeforeEffect) => {
                    return Some(worker.fail_rejected_local_command(candidate));
                }
                Err(error) => return Some(Err(error)),
            };
            match decision {
                LocalApprovalDecision::Pending => return Some(Ok(())),
                LocalApprovalDecision::Rejected => {
                    return Some(worker.fail_rejected_local_command(candidate));
                }
                LocalApprovalDecision::Approved => {}
            }
            Some(
                worker
                    .launch_local_command(candidate, workspace_id, command, prepared, principal)
                    .await,
            )
        }
    }
}
