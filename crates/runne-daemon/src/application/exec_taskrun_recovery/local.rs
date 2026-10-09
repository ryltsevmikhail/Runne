use self::helpers::{complete_cancelled, complete_local_task, reopen_exact_area};
use super::super::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::ports::EventStore;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::process_managed_area::LinuxManagedAreaRoot;
use runne_store::store::{LocalCommandAttemptState, LocalCommandRecoveryCandidate};
use std::time::Duration;

#[path = "local/cancellation.rs"]
mod cancellation;
#[path = "local/tool_areas.rs"]
mod tool_areas;

impl DaemonAutomaticTaskRuns {
    #[cfg(test)]
    pub(super) fn verify_provider_only_fixture_has_no_local_attempts(
        &self,
    ) -> Result<(), &'static str> {
        verify_empty_local_recovery_scan(|after, limit| {
            self.store.scan_local_command_recovery(after, limit)
        })
    }

    pub(super) fn recover_local_command_effects(&self) -> Result<usize, &'static str> {
        self.renew_recovery_node_lease()?;
        let mut cursor = None;
        let mut recovered = 0;
        loop {
            let page = self
                .store
                .scan_local_command_recovery(cursor, 128)
                .map_err(|_| "scan")?;
            if page.is_empty() {
                self.cleanup_settled_terminal_areas()?;
                recovered += self.recover_d2_tool_areas()?;
                return Ok(recovered);
            }
            let mut recovered_page = 0;
            helpers::each_recovery_candidate(
                &page,
                || self.renew_recovery_node_lease(),
                |candidate| {
                    if candidate.identity.node_id != self.node_id
                        || candidate.identity.node_epoch >= self.epoch
                    {
                        return Ok(());
                    }
                    self.recover_local_command(candidate)?;
                    recovered_page += 1;
                    Ok(())
                },
            )?;
            recovered += recovered_page;
            cursor = page.last().map(|item| item.identity.taskrun_id);
        }
    }

    pub(super) fn renew_recovery_node_lease(&self) -> Result<(), &'static str> {
        (self.node_lease_heartbeat)().map_err(|_| "renew_node_lease")
    }

    fn recover_local_command(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
    ) -> Result<(), &'static str> {
        self.store
            .authorize_local_command_recovery(candidate, &self.node_id, self.epoch)
            .map_err(|_| "authorize")?;
        let stream = self
            .store
            .load_task_run(candidate.identity.taskrun_id)
            .map_err(|_| "load_stream")?;
        let task = TaskRun::replay(&stream.events).map_err(|_| "replay_stream")?;
        self.recover_authorized_local_command(candidate, stream, task)
    }

    fn recover_authorized_local_command(
        &self,
        candidate: &LocalCommandRecoveryCandidate,
        stream: runne_application::ports::LoadedStream,
        task: TaskRun,
    ) -> Result<(), &'static str> {
        let root = match LinuxManagedAreaRoot::open_current_cgroup() {
            Ok(root) => root,
            Err(_) => {
                self.store
                    .mark_local_command_recovery_unconfirmed(candidate, &self.node_id, self.epoch)
                    .map_err(|_| "mark_unconfirmed")?;
                return Ok(());
            }
        };
        let area_identity = match reopen_exact_area(&root, candidate) {
            Ok(area) => area,
            Err(()) => {
                self.store
                    .mark_local_command_recovery_unconfirmed(candidate, &self.node_id, self.epoch)
                    .map_err(|_| "mark_unconfirmed")?;
                return Ok(());
            }
        };
        let area = area_identity;
        if task.state() == TaskRunState::Unrecoverable
            && candidate.state == LocalCommandAttemptState::OutcomeUnknown
        {
            let empty = match area.prove_empty() {
                Ok(empty) => empty,
                Err(_) => return Err("prove_empty"),
            };
            self.store
                .settle_local_command_outcome_unknown_recovery(
                    candidate,
                    &self.node_id,
                    self.epoch,
                    empty,
                )
                .map_err(|_| "settle_unknown")?;
            area.remove_empty().map_err(|_| "remove_area")?;
            return Ok(());
        }
        if task.state() == TaskRunState::Cancelling {
            return cancellation::recover_cancelling(self, candidate, stream, area);
        }
        let mut settled_task = task.clone();
        let mut settled_stream_version = stream.current_version;
        let mut settled_event_id = stream.last_event_id;
        if task.state() == TaskRunState::Running
            && candidate.state == LocalCommandAttemptState::Completed
        {
            if area.is_populated().map_err(|_| "check_area")? {
                let _ = area.terminate(Duration::from_secs(2));
                self.store
                    .mark_local_command_recovery_unconfirmed(candidate, &self.node_id, self.epoch)
                    .map_err(|_| "mark_unconfirmed")?;
                return Ok(());
            }
            let exit = candidate.exit_code.ok_or("missing_exit_code")?;
            if complete_local_task(
                &self.taskruns,
                candidate.identity.taskrun_id,
                stream.current_version,
                exit,
            )
            .is_err()
            {
                let latest = self
                    .store
                    .load_task_run(candidate.identity.taskrun_id)
                    .map_err(|_| "load_stream")?;
                let latest_task = TaskRun::replay(&latest.events).map_err(|_| "replay_stream")?;
                if latest_task.state() == TaskRunState::Cancelling {
                    // Single-writer startup recovery cannot observe the stream
                    // advancing between the two loads above, so this arm is a
                    // defense-in-depth check, not an expected route. It stays
                    // route-aware: a CurrentPermission attempt must never fall
                    // back to the legacy terminal service.
                    area.prove_empty().map_err(|_| "prove_empty")?;
                    let route = self
                        .store
                        .local_command_permission_route(candidate.identity.taskrun_id)
                        .map_err(|_| "complete_route_lookup")?;
                    if matches!(
                        route,
                        runne_store::store::LocalCommandPermissionRoute::CurrentPermission
                    ) {
                        return Err("complete_current");
                    }
                    complete_cancelled(
                        &self.taskruns,
                        &self.store,
                        candidate,
                        latest.current_version,
                    )
                    .map_err(|_| "complete_legacy")?;
                    area.remove_empty().map_err(|_| "remove_area")?;
                    return Ok(());
                }
                return Err("complete_taskrun");
            }
            let terminal = self
                .store
                .load_task_run(candidate.identity.taskrun_id)
                .map_err(|_| "load_stream")?;
            settled_task = TaskRun::replay(&terminal.events).map_err(|_| "replay_stream")?;
            settled_stream_version = terminal.current_version;
            settled_event_id = terminal.last_event_id;
        } else if !matches!(
            task.state(),
            TaskRunState::Succeeded | TaskRunState::Failed | TaskRunState::Cancelled
        ) {
            self.store
                .mark_local_command_recovery_unconfirmed(candidate, &self.node_id, self.epoch)
                .map_err(|_| "mark_unconfirmed")?;
            if area.terminate(Duration::from_secs(2)).is_err()
                || area.is_populated().map_err(|_| "check_area")?
            {
                return Ok(());
            }
            let empty = area.prove_empty().map_err(|_| "prove_empty")?;
            self.store
                .settle_local_command_outcome_unknown_recovery(
                    candidate,
                    &self.node_id,
                    self.epoch,
                    empty,
                )
                .map_err(|_| "settle_unknown")?;
            area.remove_empty().map_err(|_| "remove_area")?;
            return Ok(());
        }
        if area.is_populated().map_err(|_| "check_area")? {
            let _ = area.terminate(Duration::from_secs(2));
            return Err("area_populated_at_terminal");
        }
        match settled_task.state() {
            TaskRunState::Succeeded | TaskRunState::Failed => {
                let event = settled_event_id.ok_or("missing_terminal_event")?;
                self.store
                    .settle_local_command_terminal_recovery(
                        candidate,
                        &self.node_id,
                        self.epoch,
                        event,
                        settled_stream_version,
                        area.prove_empty().map_err(|_| "prove_empty")?,
                    )
                    .map_err(|_| "settle_terminal")?;
            }
            TaskRunState::Cancelled => {}
            _ => return Err("unexpected_terminal_state"),
        }
        area.remove_empty().map_err(|_| "remove_area")
    }
}

#[cfg(test)]
fn verify_empty_local_recovery_scan(
    mut scan: impl FnMut(
        Option<runne_domain::id::TaskRunId>,
        usize,
    ) -> Result<
        Vec<LocalCommandRecoveryCandidate>,
        runne_application::ports::EventStoreError,
    >,
) -> Result<(), &'static str> {
    let page = scan(None, 128).map_err(|_| "provider_fixture_local_scan")?;
    if page.is_empty() {
        Ok(())
    } else {
        Err("provider_fixture_local_attempts_present")
    }
}

#[cfg(test)]
#[path = "local/provider_fixture_tests.rs"]
mod provider_fixture_tests;

#[path = "local/helpers.rs"]
mod helpers;
#[path = "local/terminal_cleanup.rs"]
mod terminal_cleanup;
