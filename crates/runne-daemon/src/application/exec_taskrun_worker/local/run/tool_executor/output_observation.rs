use super::*;

#[derive(Default)]
pub(super) struct OutputObservation {
    pub(super) stdout_truncated: bool,
    pub(super) stderr_truncated: bool,
    pub(super) stdout_observed_bytes: u64,
    pub(super) stderr_observed_bytes: u64,
    pub(super) observed_bytes_overflowed: bool,
    pub(super) stdout_eof: bool,
    pub(super) stderr_eof: bool,
    pub(super) exit_code: Option<i32>,
}

impl OutputObservation {
    pub(super) fn observe(
        &mut self,
        chunk: &runne_platform::local_command_linux::LinuxCommandOutputChunkV1,
    ) {
        self.stdout_truncated |= chunk.stdout_truncated;
        self.stderr_truncated |= chunk.stderr_truncated;
        self.stdout_observed_bytes = self.stdout_observed_bytes.max(chunk.stdout_observed_bytes);
        self.stderr_observed_bytes = self.stderr_observed_bytes.max(chunk.stderr_observed_bytes);
        self.observed_bytes_overflowed |= chunk.observed_bytes_overflowed;
        self.stdout_eof |= chunk.stdout_eof;
        self.stderr_eof |= chunk.stderr_eof;
        self.exit_code = chunk.leader_exit_code.or(self.exit_code);
    }

    pub(super) fn into_failure(self) -> HelperRunFailure {
        HelperRunFailure {
            reason: HelperRunError::Uncertain,
            stdout: Vec::new(),
            stderr: Vec::new(),
            cleanup_proved: false,
            child_spawned: false,
            go_released: false,
            stdout_truncated: self.stdout_truncated,
            stderr_truncated: self.stderr_truncated,
            stdout_observed_bytes: self.stdout_observed_bytes,
            stderr_observed_bytes: self.stderr_observed_bytes,
            observed_bytes_overflowed: self.observed_bytes_overflowed,
            stdout_eof: self.stdout_eof,
            stderr_eof: self.stderr_eof,
            exit_code: self.exit_code,
        }
    }
}

pub(super) fn collect_output(
    child: &mut GatedLinuxChild<'_>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    observation: &mut OutputObservation,
) {
    let chunk = child.take_output();
    observation.observe(&chunk);
    if stdout.len() + chunk.stdout.len() <= STDOUT_CAP {
        stdout.extend_from_slice(&chunk.stdout);
    }
    if stderr.len() + chunk.stderr.len() <= STDERR_CAP {
        stderr.extend_from_slice(&chunk.stderr);
    }
}

pub(super) fn drain_after_stop(
    child: &mut GatedLinuxChild<'_>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
    observation: &mut OutputObservation,
) {
    for _ in 0..16 {
        if child.poll_output().is_err() {
            break;
        }
        let before = stdout.len() + stderr.len();
        collect_output(child, stdout, stderr, observation);
        if stdout.len() + stderr.len() == before {
            break;
        }
    }
}

pub(super) fn failure(reason: HelperRunError) -> HelperRunFailure {
    HelperRunFailure {
        reason,
        stdout: Vec::new(),
        stderr: Vec::new(),
        cleanup_proved: true,
        child_spawned: false,
        go_released: false,
        stdout_truncated: false,
        stderr_truncated: false,
        stdout_observed_bytes: 0,
        stderr_observed_bytes: 0,
        observed_bytes_overflowed: false,
        stdout_eof: false,
        stderr_eof: false,
        exit_code: None,
    }
}
