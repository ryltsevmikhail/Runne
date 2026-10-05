use super::output_observation::{OutputObservation, collect_output, drain_after_stop, failure};
use super::*;

/// Runs the sealed daemon image in the existing X2 gated command executor.
/// The release callback must perform the canonical durable claim/cancel gate
/// and may only release this exact stopped child.
pub(in crate::application) fn run_helper(
    files: &LinuxCommandWorkspaceFiles,
    input: &[u8],
    area: &LinuxManagedArea,
    release: impl FnOnce(&mut GatedLinuxChild<'_>) -> Result<(), ()>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<(i32, Vec<u8>, Vec<u8>), HelperRunFailure> {
    let stage = crate::application::exec_taskrun_worker::provider::d2_stage;
    stage("effect_helper_input");
    if input.len() > 16 * 1024 {
        return Err(failure(HelperRunError::Denied));
    }
    stage("effect_helper_exe_open");
    let image = File::open("/proc/self/exe").map_err(|_| failure(HelperRunError::Unavailable))?;
    stage("effect_helper_seal");
    let executable = SealedExecutableSnapshot::from_held_file(&image)
        .map_err(|_| failure(HelperRunError::Unavailable))?;
    let spec = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&executable),
        workspace: files.workspace(),
        cwd: files.cwd(),
        argv: vec![
            OsString::from("runned"),
            OsString::from("--safe-tool-helper-v1"),
        ],
        env: Vec::new(),
    };
    stage("effect_helper_preflight");
    spec.preflight()
        .map_err(|_| failure(HelperRunError::Unavailable))?;
    let stdout_cap = fixture_truncated_read_cap().unwrap_or(STDOUT_CAP);
    let limits = LinuxCommandOutputLimitsV1::new(stdout_cap, STDERR_CAP)
        .map_err(|_| failure(HelperRunError::Unavailable))?;
    stage("effect_helper_spawn");
    let mut child = spawn_gated_with_io(&spec, area, input, limits)
        .map_err(|_| failure(HelperRunError::Unavailable))?;
    stage("effect_helper_gate_release");
    if release(&mut child).is_err() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut observation = OutputObservation::default();
        let stopped = supervise_gated_child(&mut child, area, Duration::from_millis(1), |child| {
            let _ = child.poll_output();
            collect_output(child, &mut stdout, &mut stderr, &mut observation);
            Ok(X2Observation::Stop)
        });
        drain_after_stop(&mut child, &mut stdout, &mut stderr, &mut observation);
        stage("effect_helper_gate_failed");
        return Err(HelperRunFailure {
            reason: HelperRunError::Uncertain,
            stdout,
            stderr,
            cleanup_proved: stopped.is_ok(),
            child_spawned: true,
            go_released: child.was_released(),
            exit_code: observation.exit_code,
            ..observation.into_failure()
        });
    }
    stage("effect_helper_supervise");
    let deadline = Instant::now() + TOOL_OPERATION_DEADLINE;
    let mut stdout = Vec::with_capacity(STDOUT_CAP);
    let mut stderr = Vec::with_capacity(STDERR_CAP);
    let mut stop_reason = None;
    let mut observation = OutputObservation::default();
    let observed = supervise_gated_child(&mut child, area, Duration::from_millis(5), |child| {
        if cancelled() {
            stop_reason = Some(HelperRunError::Cancelled);
            return Ok(X2Observation::Stop);
        }
        if Instant::now() >= deadline {
            stop_reason = Some(HelperRunError::TimedOut);
            return Ok(X2Observation::Stop);
        }
        if child.poll_output().is_err() {
            stop_reason = Some(HelperRunError::Uncertain);
            return Ok(X2Observation::Stop);
        }
        let chunk = child.take_output();
        observation.observe(&chunk);
        if chunk.stdout_truncated || chunk.stderr_truncated {
            stop_reason = Some(HelperRunError::Uncertain);
            stdout.extend_from_slice(&chunk.stdout);
            stderr.extend_from_slice(&chunk.stderr);
            return Ok(X2Observation::Stop);
        }
        if stdout.len() + chunk.stdout.len() > STDOUT_CAP
            || stderr.len() + chunk.stderr.len() > STDERR_CAP
        {
            stop_reason = Some(HelperRunError::Uncertain);
            return Ok(X2Observation::Stop);
        }
        stdout.extend_from_slice(&chunk.stdout);
        stderr.extend_from_slice(&chunk.stderr);
        match child.try_wait() {
            Ok(Some(code)) if chunk.stdout_eof && chunk.stderr_eof => {
                return Ok(X2Observation::Complete(code));
            }
            Ok(_) => {}
            Err(_) => {
                stop_reason = Some(HelperRunError::Uncertain);
                return Ok(X2Observation::Stop);
            }
        }
        Ok(X2Observation::Continue)
    });
    match observed {
        Ok(X2Outcome::Complete(code)) => {
            stage("effect_helper_complete");
            Ok((code, stdout, stderr))
        }
        Ok(X2Outcome::Stopped) => {
            // The child may have emitted a receipt as cancellation raced with
            // the final write. Preserve it for durable late-result auditing.
            drain_after_stop(&mut child, &mut stdout, &mut stderr, &mut observation);
            stage("effect_helper_stopped");
            Err(HelperRunFailure {
                reason: stop_reason.unwrap_or(HelperRunError::Uncertain),
                stdout,
                stderr,
                cleanup_proved: true,
                child_spawned: true,
                go_released: true,
                exit_code: observation.exit_code,
                ..observation.into_failure()
            })
        }
        Err(()) => {
            stage("effect_helper_supervisor_error");
            Err(HelperRunFailure {
                reason: HelperRunError::Uncertain,
                stdout,
                stderr,
                cleanup_proved: false,
                child_spawned: true,
                go_released: true,
                exit_code: observation.exit_code,
                ..observation.into_failure()
            })
        }
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
