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
