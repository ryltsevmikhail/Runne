use super::super::run::x2_supervisor::{self, X2Observation, X2Outcome};
use super::*;
use runne_application::permission_modes::LocalCommandPermissionBindingV1;
use runne_application::ports::{
    TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunLeaseRenewal,
};
use runne_domain::id::CommandId;
use runne_domain::task_run::{TaskRun, TaskRunState};
use runne_platform::local_command_linux::{LinuxLeaderExitKindV1, PermissionChildV1};
use runne_platform::process_managed_area::LinuxManagedArea;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
pub(super) struct PermissionTerminalOutput {
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) stdout_observed: u64,
    pub(super) stderr_observed: u64,
    pub(super) stdout_truncated: bool,
    pub(super) stderr_truncated: bool,
    pub(super) exit: LinuxLeaderExitKindV1,
    pub(super) stopped_for_policy: bool,
}
struct OutputCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_observed: u64,
    stderr_observed: u64,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout_eof: bool,
    stderr_eof: bool,
    overflowed: bool,
}
impl OutputCapture {
    fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_observed: 0,
            stderr_observed: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_eof: false,
            stderr_eof: false,
            overflowed: false,
        }
    }
    fn drain(&mut self, child: &mut PermissionChildV1<'_>) -> Result<(), ()> {
        child.poll_output().map_err(|_| ())?;
        let chunk = child.take_output();
        if chunk.stdout_observed_bytes < self.stdout_observed
            || chunk.stderr_observed_bytes < self.stderr_observed
            || self.stdout.len().saturating_add(chunk.stdout.len()) > 65_536
            || self.stderr.len().saturating_add(chunk.stderr.len()) > 65_536
        {
            return Err(());
        }
        self.stdout.extend_from_slice(&chunk.stdout);
        self.stderr.extend_from_slice(&chunk.stderr);
        self.stdout_observed = chunk.stdout_observed_bytes;
        self.stderr_observed = chunk.stderr_observed_bytes;
        self.stdout_truncated |= chunk.stdout_truncated;
        self.stderr_truncated |= chunk.stderr_truncated;
        self.stdout_eof = chunk.stdout_eof;
        self.stderr_eof = chunk.stderr_eof;
        self.overflowed |= chunk.observed_bytes_overflowed;
        if self.overflowed {
            return Err(());
        }
        Ok(())
    }
    fn at_eof(&self) -> bool {
        self.stdout_eof && self.stderr_eof
    }
}
pub(super) fn supervise(
    store: &StoreTransaction,
    roots: &super::super::super::RootAdmissionGateway,
    identity: &TaskRunAssignmentIdentity,
    binding: &LocalCommandPermissionBindingV1,
    area: &LinuxManagedArea,
    child: &mut PermissionChildV1<'_>,
    current_epoch: &AtomicU64,
) -> Result<PermissionTerminalOutput, AutomaticTaskRunError> {
    let mut output = OutputCapture::new();
    let mut stop_reason = None;
    let mut renewal_at = Instant::now() + Duration::from_secs(30);
    let runtime_ms = binding
        .limits()
        .max_runtime_ms()
        .min(binding.scope().lifetime_ms);
    let Some(deadline) = Instant::now().checked_add(Duration::from_millis(runtime_ms)) else {
        persist_stop(store, identity, binding, 6, &mut stop_reason);
        return Err(AutomaticTaskRunError::Uncertain);
    };
    let observed =
        x2_supervisor::supervise_child(child, area, Duration::from_millis(100), |child| {
            if current_epoch.load(Ordering::Acquire) != identity.node_epoch {
                persist_stop(store, identity, binding, 6, &mut stop_reason);
                return Ok(X2Observation::Stop);
            }
            match store.local_command_permission_stop_reason(identity, binding) {
                Ok(Some(reason)) => {
                    stop_reason = Some(reason);
                    return Ok(X2Observation::Stop);
                }
                Err(_) => {
                    stop_reason = Some(6);
                    return Ok(X2Observation::Stop);
                }
                Ok(None) => {}
            }
            if Instant::now() >= renewal_at {
                if store
                    .renew_taskrun_assignment_lease(TaskRunLeaseRenewal {
                        identity: identity.clone(),
                        renewal_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
                        lease_duration_ms: 300_000,
                    })
                    .is_err()
                {
                    persist_stop(store, identity, binding, 6, &mut stop_reason);
                    return Ok(X2Observation::Stop);
                }
                renewal_at = Instant::now() + Duration::from_secs(30);
            }
            let stream = store.load_task_run(identity.taskrun_id).map_err(|_| ())?;
            let task = TaskRun::replay(&stream.events).map_err(|_| ())?;
            if task.state() == TaskRunState::Cancelling {
                persist_stop(store, identity, binding, 1, &mut stop_reason);
                return Ok(X2Observation::Stop);
            }
            if task.state() != TaskRunState::Running {
                persist_stop(store, identity, binding, 6, &mut stop_reason);
                return Ok(X2Observation::Stop);
            }
            if Instant::now() >= deadline
                || binding.approval().expires_at_unix_ms <= super::super::now_millis()
                || binding
                    .selection()
                    .expires_at_unix_ms
                    .is_some_and(|expiry| expiry <= super::super::now_millis())
            {
                persist_stop(store, identity, binding, 5, &mut stop_reason);
                return Ok(X2Observation::Stop);
            }
            if let Some(reason) =
                super::policy_check::current_policy_stop_reason(roots, store, binding)
            {
                persist_stop(store, identity, binding, reason, &mut stop_reason);
                return Ok(X2Observation::Stop);
            }
            if output.drain(child).is_err() {
                persist_stop(store, identity, binding, 6, &mut stop_reason);
                return Ok(X2Observation::Stop);
            }
            match child.try_wait() {
                Ok(Some(exit)) if output.at_eof() => Ok(X2Observation::PermissionComplete(exit)),
                Ok(Some(_)) | Ok(None) => Ok(X2Observation::Continue),
                Err(_) => {
                    persist_stop(store, identity, binding, 6, &mut stop_reason);
                    Ok(X2Observation::Stop)
                }
            }
        });
    let exit = match observed {
        Ok(X2Outcome::PermissionComplete(exit)) => exit,
        Ok(X2Outcome::Stopped) => {
            for _ in 0..32 {
                if output.at_eof() {
                    break;
                }
                if output.drain(child).is_err() {
                    return Err(AutomaticTaskRunError::Uncertain);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if !output.at_eof() {
                return Err(AutomaticTaskRunError::Uncertain);
            }
            match stop_reason {
                Some(1..=5) => child
                    .try_wait()
                    .map_err(|_| AutomaticTaskRunError::Uncertain)?
                    .ok_or(AutomaticTaskRunError::Uncertain)?,
                Some(6) | None => {
                    return Err(AutomaticTaskRunError::Uncertain);
                }
                Some(_) => return Err(AutomaticTaskRunError::Uncertain),
            }
        }
        Ok(X2Outcome::Complete(_)) | Err(()) => {
            return Err(AutomaticTaskRunError::Uncertain);
        }
    };
    child
        .terminal_evidence()
        .and_then(|evidence| evidence.revalidate_empty_area())
        .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    // Test-support hook (legacy precedent run/supervise.rs): while the
    // after-exit barrier is engaged the factual leader exit is recorded
    // durably before the workflow terminal commit, exactly like the legacy
    // two-phase settlement; production keeps the atomic terminal UoW.
    if super::super::run::test_barrier::after_exit_split_requested() && stop_reason.is_none() {
        let empty = area
            .prove_empty()
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        store
            .record_local_command_permission_exit(
                identity,
                binding,
                &area.identity().to_bytes(),
                legacy_exit_code(exit),
                empty,
            )
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
    }
    // Test-support hook (legacy precedent run/supervise.rs): parks the worker
    // between the observed factual child exit and the terminal commit so
    // fault tests can race a late cancellation against the completion.
    if super::super::run::test_barrier::pause_at(super::super::run::test_barrier::Point::AfterExit)
        .is_err()
    {
        return Err(AutomaticTaskRunError::Uncertain);
    }
    Ok(PermissionTerminalOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        stdout_observed: output.stdout_observed,
        stderr_observed: output.stderr_observed,
        stdout_truncated: output.stdout_truncated,
        stderr_truncated: output.stderr_truncated,
        exit,
        stopped_for_policy: matches!(stop_reason, Some(2..=5)),
    })
}
fn persist_stop(
    store: &StoreTransaction,
    identity: &TaskRunAssignmentIdentity,
    binding: &LocalCommandPermissionBindingV1,
    reason: u8,
    observed: &mut Option<u8>,
) {
    *observed = Some(
        store
            .record_local_command_permission_stop(identity, binding, reason)
            .unwrap_or(6),
    );
}

/// Maps the observed leader exit onto the legacy flat code kept by the
/// attempt row and the factual-exit record.
fn legacy_exit_code(exit: LinuxLeaderExitKindV1) -> i32 {
    match exit {
        LinuxLeaderExitKindV1::Exited { code } => i32::from(code),
        LinuxLeaderExitKindV1::Signaled { signal, .. } => 128 + signal,
    }
}
