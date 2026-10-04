use super::*;
use runne_application::ports::TaskRunAssignmentIdentity;
use runne_application::service::ClaimTaskRunInput;

impl DaemonAutomaticTaskRuns {
    pub(super) fn fail_rejected_local_command(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<(), AutomaticTaskRunError> {
        let epoch = self
            .current_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let claim = self
            .taskruns
            .claim_task_run(
                &Self::runtime_context(),
                ClaimTaskRunInput {
                    taskrun_id: candidate.taskrun_id,
                    expected_version: candidate.current_version,
                    node_id: self.node_id.clone(),
                    node_epoch: epoch,
                    capability_descriptor: "linux-executor-v1".into(),
                    lease_duration_ms: 30_000,
                },
                &self.store,
            )
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let receipt = match claim {
            runne_application::ports::TaskRunClaimResult::Committed(value)
            | runne_application::ports::TaskRunClaimResult::Duplicate(value) => value,
        };
        self.release_before_effect(
            TaskRunAssignmentIdentity {
                taskrun_id: receipt.taskrun_id,
                attempt_id: receipt.attempt_id,
                node_id: receipt.node_id,
                node_epoch: receipt.node_epoch,
                fence: receipt.fence,
            },
            receipt.new_version,
        )
    }
}
