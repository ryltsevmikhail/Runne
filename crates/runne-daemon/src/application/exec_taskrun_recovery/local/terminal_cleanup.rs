use super::DaemonAutomaticTaskRuns;
use runne_application::ports::EventStore;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::process_managed_area::{LinuxManagedAreaRoot, ManagedAreaIdentity};
use runne_store::store::{LocalCommandAttemptState, LocalCommandRecoveryCandidate};

impl DaemonAutomaticTaskRuns {
    pub(super) fn cleanup_settled_terminal_areas(&self) -> Result<(), &'static str> {
        let mut cursor = None;
        loop {
            let page = match self.store.scan_local_command_terminal_cleanup(cursor, 128) {
                Ok(page) => page,
                Err(_) => {
                    tracing::warn!(
                        stage = "cleanup_scan",
                        "local terminal area cleanup deferred"
                    );
                    return Ok(());
                }
            };
            if page.is_empty() {
                return Ok(());
            }
            let root = match LinuxManagedAreaRoot::open_current_cgroup() {
                Ok(root) => root,
                Err(_) => {
                    tracing::warn!(
                        stage = "cleanup_root",
                        "local terminal area cleanup deferred"
                    );
                    return Ok(());
                }
            };
            for candidate in &page {
                if (self.node_lease_heartbeat)().is_err() {
                    tracing::warn!(
                        stage = "cleanup_lease",
                        "local terminal area cleanup deferred"
                    );
                    return Ok(());
                }
                if self.cleanup_one_terminal_area(&root, candidate).is_err() {
                    tracing::warn!(
                        stage = "cleanup_candidate",
                        "local terminal area cleanup deferred"
                    );
                }
                if (self.node_lease_heartbeat)().is_err() {
                    tracing::warn!(
                        stage = "cleanup_lease",
                        "local terminal area cleanup deferred"
                    );
                    return Ok(());
                }
            }
            cursor = page.last().map(|candidate| candidate.identity.taskrun_id);
        }
    }

    fn cleanup_one_terminal_area(
        &self,
        root: &LinuxManagedAreaRoot,
        candidate: &LocalCommandRecoveryCandidate,
    ) -> Result<(), &'static str> {
        if candidate.identity.node_id != self.node_id || candidate.identity.node_epoch >= self.epoch
        {
            return Ok(());
        }
        self.store
            .authorize_local_command_recovery(candidate, &self.node_id, self.epoch)
            .map_err(|_| "cleanup_authorize")?;
        let stream = self
            .store
            .load_task_run(candidate.identity.taskrun_id)
            .map_err(|_| "cleanup_load")?;
        let task = TaskRun::replay(&stream.events).map_err(|_| "cleanup_replay")?;
        let success_or_failure =
            matches!(task.state(), TaskRunState::Succeeded | TaskRunState::Failed)
                && candidate.state == LocalCommandAttemptState::Completed
                && candidate.exit_code.is_some();
        let cancelled = task.state() == TaskRunState::Cancelled
            && matches!(
                (candidate.state, candidate.exit_code),
                // Live worker cancellations keep the observed leader code;
                // recovery-owned ones invent none (NULL).
                (LocalCommandAttemptState::Cancelled, _)
                    | (LocalCommandAttemptState::Completed, Some(_))
            );
        if !success_or_failure && !cancelled {
            return Err("cleanup_mismatch");
        }
        let identity = ManagedAreaIdentity::from_bytes(&candidate.area_identity)
            .map_err(|_| "cleanup_identity")?;
        root.remove_area_if_present(identity)
            .map_err(|_| "cleanup_area")?;
        Ok(())
    }
}
