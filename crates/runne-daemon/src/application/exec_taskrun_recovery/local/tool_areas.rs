use super::super::super::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::ports::ExecutionNodeId;
use runne_platform::process_managed_area::{
    LinuxManagedAreaRoot, ManagedAreaBinding, ManagedAreaIdentity,
};
use std::time::Duration;

impl DaemonAutomaticTaskRuns {
    pub(super) fn recover_d2_tool_areas(&self) -> Result<usize, &'static str> {
        self.renew_recovery_node_lease()?;
        let root = LinuxManagedAreaRoot::open_current_cgroup().ok();
        let mut cursor = None;
        let mut recovered = 0usize;
        loop {
            let page = self
                .store
                .scan_taskrun_tool_area_recovery(cursor, 64)
                .map_err(|_| "scan_tool_areas")?;
            if page.is_empty() {
                return Ok(recovered);
            }
            for candidate in &page {
                self.renew_recovery_node_lease()?;
                if candidate.assignment.node_id != self.node_id
                    || candidate.assignment.node_epoch >= self.epoch
                {
                    continue;
                }
                self.store
                    .authorize_taskrun_tool_area_recovery(candidate, &self.node_id, self.epoch)
                    .map_err(|_| "authorize_tool_area")?;
                let Some(root) = root.as_ref() else {
                    self.store
                        .mark_taskrun_tool_area_recovery_uncertain(
                            candidate,
                            &self.node_id,
                            self.epoch,
                        )
                        .map_err(|_| "mark_tool_area_uncertain")?;
                    continue;
                };
                let identity = match ManagedAreaIdentity::from_bytes(&candidate.area_identity) {
                    Ok(identity) => identity,
                    Err(_) => continue,
                };
                let binding = ManagedAreaBinding::new(
                    *candidate.key.taskrun_id.as_bytes(),
                    *candidate.key.attempt_id.as_bytes(),
                    candidate.key.managed_area_nonce(candidate.semantic_digest),
                )
                .map_err(|_| "tool_area_binding")?;
                let area = match root.reopen_area(identity.clone(), binding) {
                    Ok(area) => area,
                    Err(_) => {
                        self.store
                            .mark_taskrun_tool_area_recovery_uncertain(
                                candidate,
                                &self.node_id,
                                self.epoch,
                            )
                            .map_err(|_| "mark_tool_area_uncertain")?;
                        continue;
                    }
                };
                let stopped = area.terminate(Duration::from_secs(2)).is_ok()
                    && area
                        .is_populated()
                        .map(|populated| !populated)
                        .unwrap_or(false);
                if !stopped {
                    self.store
                        .mark_taskrun_tool_area_recovery_uncertain(
                            candidate,
                            &self.node_id,
                            self.epoch,
                        )
                        .map_err(|_| "mark_tool_area_uncertain")?;
                    continue;
                }
                let empty = area.prove_empty().map_err(|_| "tool_area_proof")?;
                self.store
                    .record_taskrun_tool_area_recovered(
                        candidate,
                        &ExecutionNodeId(self.node_id.0.clone()),
                        self.epoch,
                        &identity,
                        &empty,
                    )
                    .map_err(|_| "persist_tool_area_proof")?;
                area.remove_empty().map_err(|_| "remove_tool_area")?;
                recovered = recovered.checked_add(1).ok_or("tool_area_count_overflow")?;
            }
            cursor = page.last().map(|candidate| {
                (
                    candidate.key.taskrun_id,
                    candidate.key.attempt_id,
                    candidate.key.cycle_id,
                    candidate.key.proposal_index,
                )
            });
        }
    }
}
