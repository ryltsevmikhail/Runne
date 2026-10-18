use std::time::Duration;

/// Maximum retained bytes for each command output stream.
pub const MAX_LOCAL_COMMAND_CAPTURE_BYTES: usize = 64 * 1024;

/// Checked data limits for one portable local-command invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalInvocationLimitsV1 {
    stdout_capture_bytes: u64,
    stderr_capture_bytes: u64,
    max_runtime_ms: u64,
}

/// Rejection while constructing checked local invocation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalInvocationLimitsError {
    /// One output stream exceeds its independent retained-byte cap.
    CaptureLimitExceeded,
    /// The invocation must have a positive monotonic runtime bound.
    RuntimeMustBePositive,
    /// A configured value cannot be represented by this target.
    Unrepresentable,
}

impl LocalInvocationLimitsV1 {
    /// Validates independent stream caps and a positive, representable runtime.
    pub fn checked(
        stdout_capture_bytes: u64,
        stderr_capture_bytes: u64,
        max_runtime_ms: u64,
    ) -> Result<Self, LocalInvocationLimitsError> {
        if stdout_capture_bytes > MAX_LOCAL_COMMAND_CAPTURE_BYTES as u64
            || stderr_capture_bytes > MAX_LOCAL_COMMAND_CAPTURE_BYTES as u64
        {
            return Err(LocalInvocationLimitsError::CaptureLimitExceeded);
        }
        if max_runtime_ms == 0 {
            return Err(LocalInvocationLimitsError::RuntimeMustBePositive);
        }
        usize::try_from(stdout_capture_bytes)
            .map_err(|_| LocalInvocationLimitsError::Unrepresentable)?;
        usize::try_from(stderr_capture_bytes)
            .map_err(|_| LocalInvocationLimitsError::Unrepresentable)?;
        duration_from_millis(max_runtime_ms)?;
        Ok(Self {
            stdout_capture_bytes,
            stderr_capture_bytes,
            max_runtime_ms,
        })
    }

    /// Returns the retained stdout cap; zero discards bytes while draining.
    pub const fn stdout_capture_bytes(self) -> u64 {
        self.stdout_capture_bytes
    }

    /// Returns the retained stderr cap; zero discards bytes while draining.
    pub const fn stderr_capture_bytes(self) -> u64 {
        self.stderr_capture_bytes
    }

    /// Returns the one-invocation duration bound in milliseconds.
    pub const fn max_runtime_ms(self) -> u64 {
        self.max_runtime_ms
    }

    /// Returns the fixed one-GO allowance represented by this value.
    pub const fn admitted_invocations(self) -> u8 {
        1
    }

    /// Converts a validated cap to the native target's `usize` without truncation.
    pub fn stdout_capture_bytes_usize(self) -> Result<usize, LocalInvocationLimitsError> {
        usize::try_from(self.stdout_capture_bytes)
            .map_err(|_| LocalInvocationLimitsError::Unrepresentable)
    }

    /// Converts a validated cap to the native target's `usize` without truncation.
    pub fn stderr_capture_bytes_usize(self) -> Result<usize, LocalInvocationLimitsError> {
        usize::try_from(self.stderr_capture_bytes)
            .map_err(|_| LocalInvocationLimitsError::Unrepresentable)
    }

    /// Converts the millisecond bound exactly to a monotonic runtime duration.
    pub fn max_runtime(self) -> Result<Duration, LocalInvocationLimitsError> {
        duration_from_millis(self.max_runtime_ms)
    }
}

fn duration_from_millis(milliseconds: u64) -> Result<Duration, LocalInvocationLimitsError> {
    if milliseconds == 0 {
        return Err(LocalInvocationLimitsError::RuntimeMustBePositive);
    }
    let seconds = milliseconds / 1_000;
    let remainder_ms = u32::try_from(milliseconds % 1_000)
        .map_err(|_| LocalInvocationLimitsError::Unrepresentable)?;
    let nanoseconds = remainder_ms
        .checked_mul(1_000_000)
        .ok_or(LocalInvocationLimitsError::Unrepresentable)?;
    Ok(Duration::new(seconds, nanoseconds))
}
