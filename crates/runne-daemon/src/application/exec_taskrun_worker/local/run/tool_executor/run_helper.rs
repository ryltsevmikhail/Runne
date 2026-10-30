use super::output_observation::{OutputObservation, failure};
use super::*;
use runne_platform::local_command_linux::{
    LinuxCommandOutputLimitsV1, LinuxLeaderExitKindV1, PermissionHelperChildV1,
    PreparedToolHelperV1,
};

/// Runs the prepared fixed helper and releases only its actual tagged child.
pub(in crate::application) fn run_helper<'area>(
    helper: PreparedToolHelperV1,
    input: &[u8],
    area: &'area LinuxManagedArea,
    release: impl FnOnce(&mut PermissionHelperChildV1<'area>) -> Result<(), ()>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<HelperRunOutput<'area>, HelperRunFailure> {
    let stage = crate::application::exec_taskrun_worker::provider::d2_stage;
    if input.len() > 16 * 1024 {
        return Err(failure(HelperRunError::Denied));
    }
    let stdout_cap = fixture_truncated_read_cap().unwrap_or(STDOUT_CAP);
    let limits = LinuxCommandOutputLimitsV1::new(stdout_cap, STDERR_CAP)
        .map_err(|_| failure(HelperRunError::Unavailable))?;
    stage("effect_helper_spawn");
    let mut child = helper
        .spawn_helper(input, area, limits)
        .map_err(|_| failure(HelperRunError::Unavailable))?;
    stage("effect_helper_gate_release");
    if release(&mut child).is_err() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut observation = OutputObservation::default();
        let stopped = matches!(
            supervise_child(&mut child, area, Duration::from_millis(5), |_| {
                Ok(X2Observation::Stop)
            }),
            Ok(X2Outcome::Stopped)
        );
        drain_after_stop(&mut child, &mut stdout, &mut stderr, &mut observation);
        stage("effect_helper_gate_failed");
        return Err(failure_with(
            HelperRunError::Uncertain,
            stdout,
            stderr,
            observation,
            stopped,
            child.was_released(),
        ));
    }
    stage("effect_helper_supervise");
    let operation_deadline = serde_json::from_slice::<serde_json::Value>(input)
        .ok()
        .filter(|v| v["operation"] == "Coding" && v["tool_name"] == "workspace.command.run")
        .and_then(|v| v["arguments"]["timeout_ms"].as_u64())
        .filter(|v| (1..=120000).contains(v))
        .map_or(TOOL_OPERATION_DEADLINE, |v| {
            Duration::from_millis(v.saturating_add(1000))
        });
    let deadline = Instant::now() + operation_deadline;
    let mut stdout = Vec::with_capacity(STDOUT_CAP);
    let mut stderr = Vec::with_capacity(STDERR_CAP);
    let mut observation = OutputObservation::default();
    let mut stop_reason = None;
    let mut observed_exit = None;
    let supervised = supervise_child(&mut child, area, Duration::from_millis(5), |child| {
        let reason = if cancelled() {
            Some(HelperRunError::Cancelled)
        } else if Instant::now() >= deadline {
            Some(HelperRunError::TimedOut)
        } else if child.poll_output().is_err() {
            Some(HelperRunError::Uncertain)
        } else {
            None
        };
        if let Some(reason) = reason {
            stop_reason = Some(reason);
            return Ok(X2Observation::Stop);
        }
        let chunk = child.take_output();
        observation.observe(&chunk);
        let overflow = chunk.stdout_truncated
            || chunk.stderr_truncated
            || stdout.len() + chunk.stdout.len() > STDOUT_CAP
            || stderr.len() + chunk.stderr.len() > STDERR_CAP;
        if stdout.len() + chunk.stdout.len() <= STDOUT_CAP {
            stdout.extend_from_slice(&chunk.stdout);
        }
        if stderr.len() + chunk.stderr.len() <= STDERR_CAP {
            stderr.extend_from_slice(&chunk.stderr);
        }
        if overflow {
            stop_reason = Some(HelperRunError::Uncertain);
            return Ok(X2Observation::Stop);
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                observed_exit = Some(exit);
                if chunk.stdout_eof && chunk.stderr_eof {
                    let code = match exit {
                        LinuxLeaderExitKindV1::Exited { code } => i32::from(code),
                        LinuxLeaderExitKindV1::Signaled { signal, .. } => 128 + signal,
                    };
                    Ok(X2Observation::Complete(code))
                } else {
                    Ok(X2Observation::Continue)
                }
            }
            Ok(None) => Ok(X2Observation::Continue),
            Err(_) => {
                stop_reason = Some(HelperRunError::Uncertain);
                Ok(X2Observation::Stop)
            }
        }
    });
    match supervised {
        Ok(X2Outcome::Complete(_)) => {
            let terminal = match child.terminal_evidence() {
                Ok(terminal) => terminal,
                Err(_) => {
                    return Err(failure_with(
                        HelperRunError::Uncertain,
                        stdout,
                        stderr,
                        observation,
                        true,
                        true,
                    ));
                }
            };
            let exit_kind = terminal.leader_exit_kind();
            if observed_exit != Some(exit_kind) {
                return Err(failure_with(
                    HelperRunError::Uncertain,
                    stdout,
                    stderr,
                    observation,
                    true,
                    true,
                ));
            }
            stage("effect_helper_complete");
            Ok(HelperRunOutput {
                child,
                stdout,
                stderr,
            })
        }
        Ok(X2Outcome::PermissionComplete(_)) => Err(failure_with(
            HelperRunError::Uncertain,
            stdout,
            stderr,
            observation,
            true,
            true,
        )),
        Ok(X2Outcome::Stopped) => {
            drain_after_stop(&mut child, &mut stdout, &mut stderr, &mut observation);
            stage("effect_helper_stopped");
            Err(failure_with(
                stop_reason.unwrap_or(HelperRunError::Uncertain),
                stdout,
                stderr,
                observation,
                true,
                true,
            ))
        }
        Err(()) => {
            drain_after_stop(&mut child, &mut stdout, &mut stderr, &mut observation);
            Err(failure_with(
                HelperRunError::Uncertain,
                stdout,
                stderr,
                observation,
                false,
                true,
            ))
        }
    }
}

fn drain_after_stop(
    child: &mut PermissionHelperChildV1<'_>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    observation: &mut OutputObservation,
) {
    for _ in 0..16 {
        if child.poll_output().is_err() {
            break;
        }
        let chunk = child.take_output();
        observation.observe(&chunk);
        if stdout.len() + chunk.stdout.len() <= STDOUT_CAP {
            stdout.extend_from_slice(&chunk.stdout);
        }
        if stderr.len() + chunk.stderr.len() <= STDERR_CAP {
            stderr.extend_from_slice(&chunk.stderr);
        }
        if chunk.stdout_eof && chunk.stderr_eof {
            break;
        }
    }
}

fn failure_with(
    reason: HelperRunError,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    observation: OutputObservation,
    cleanup_proved: bool,
    go_released: bool,
) -> HelperRunFailure {
    HelperRunFailure {
        reason,
        stdout,
        stderr,
        cleanup_proved,
        child_spawned: true,
        go_released,
        stdout_truncated: observation.stdout_truncated,
        stderr_truncated: observation.stderr_truncated,
        stdout_observed_bytes: observation.stdout_observed_bytes,
        stderr_observed_bytes: observation.stderr_observed_bytes,
        observed_bytes_overflowed: observation.observed_bytes_overflowed,
        stdout_eof: observation.stdout_eof,
        stderr_eof: observation.stderr_eof,
        exit_code: observation.exit_code,
    }
}

#[cfg(all(
    target_os = "linux",
    feature = "desktop-protected",
    feature = "test-support",
    not(test)
))]
fn fixture_truncated_read_cap() -> Option<usize> {
    use std::ffi::OsStr;

    (std::env::var_os("RUNNE_TEST_T1_TRUST_COMPOSITION").as_deref() == Some(OsStr::new("1"))
        && std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() == Ok("truncated-read-result"))
    .then_some(1)
}

#[cfg(not(all(
    target_os = "linux",
    feature = "desktop-protected",
    feature = "test-support",
    not(test)
)))]
const fn fixture_truncated_read_cap() -> Option<usize> {
    None
}
