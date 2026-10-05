use super::spec::LinuxCommandError;

pub(super) const MAX_STDIN_BYTES: usize = 16 * 1024;
pub(super) const MAX_STREAM_CAPTURE_BYTES: usize = 64 * 1024;
pub(super) const OUTPUT_DRAIN_QUANTUM: usize = 8 * 1024;
pub(super) const OUTPUT_READ_CHUNK: usize = 4 * 1024;

/// Per-stream output caps for one gated command invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxCommandOutputLimitsV1 {
    stdout_bytes: usize,
    stderr_bytes: usize,
}

impl LinuxCommandOutputLimitsV1 {
    /// Creates bounded output limits; each stream is capped at 64 KiB.
    pub fn new(stdout_bytes: usize, stderr_bytes: usize) -> Result<Self, LinuxCommandError> {
        if stdout_bytes > MAX_STREAM_CAPTURE_BYTES || stderr_bytes > MAX_STREAM_CAPTURE_BYTES {
            return Err(LinuxCommandError::Invalid);
        }
        Ok(Self {
            stdout_bytes,
            stderr_bytes,
        })
    }

    pub(super) const fn stdout_bytes(self) -> usize {
        self.stdout_bytes
    }

    pub(super) const fn stderr_bytes(self) -> usize {
        self.stderr_bytes
    }
}

/// Newly collected output since the previous `take_output` call.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct LinuxCommandOutputChunkV1 {
    /// Bytes retained from standard output under the configured lifetime cap.
    pub stdout: Vec<u8>,
    /// Bytes retained from standard error under the configured lifetime cap.
    pub stderr: Vec<u8>,
    /// Sticky indication that standard output exceeded its cap.
    pub stdout_truncated: bool,
    /// Sticky indication that standard error exceeded its cap.
    pub stderr_truncated: bool,
    /// Total stdout bytes drained, including bytes omitted after the cap.
    pub stdout_observed_bytes: u64,
    /// Total stderr bytes drained, including bytes omitted after the cap.
    pub stderr_observed_bytes: u64,
    /// True if either total saturated instead of wrapping.
    pub observed_bytes_overflowed: bool,
    /// True only after all writers to standard output have closed.
    pub stdout_eof: bool,
    /// True only after all writers to standard error have closed.
    pub stderr_eof: bool,
    /// Direct leader exit status, independent of pipe EOF and cgroup emptiness.
    pub leader_exit_code: Option<i32>,
}

impl std::fmt::Debug for LinuxCommandOutputChunkV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinuxCommandOutputChunkV1")
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .field("stdout_observed_bytes", &self.stdout_observed_bytes)
            .field("stderr_observed_bytes", &self.stderr_observed_bytes)
            .field("observed_bytes_overflowed", &self.observed_bytes_overflowed)
            .field("stdout_eof", &self.stdout_eof)
            .field("stderr_eof", &self.stderr_eof)
            .field("leader_exit_code", &self.leader_exit_code)
            .finish()
    }
}
