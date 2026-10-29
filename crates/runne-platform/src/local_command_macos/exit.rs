//! Terminal classification for a macOS command leader.

/// Copyable classification data for a command leader's terminal outcome.
/// This data alone grants no execution or effect authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxLeaderExitKindV1 {
    /// The leader exited normally.
    Exited {
        /// Exit code returned by the operating system, from 0 through 255.
        code: u8,
    },
    /// The leader terminated because it received a signal.
    Signaled {
        /// Signal number reported by the operating system.
        signal: i32,
        /// Whether the operating system marked the signal termination as a core dump.
        core_dumped: bool,
    },
}

/// Read-only outcome data from a successful wait of the command leader.
#[derive(Debug, PartialEq, Eq)]
pub struct LinuxLeaderExitObservationV1 {
    kind: LinuxLeaderExitKindV1,
}

impl LinuxLeaderExitObservationV1 {
    /// Classifies a completed standard-library exit status.
    #[must_use]
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt as _;
        let kind = match (status.code(), status.signal()) {
            (Some(code), _) => LinuxLeaderExitKindV1::Exited {
                code: u8::try_from(code).unwrap_or(255),
            },
            (None, Some(signal)) => LinuxLeaderExitKindV1::Signaled {
                signal,
                core_dumped: status.core_dumped(),
            },
            (None, None) => LinuxLeaderExitKindV1::Signaled {
                signal: 0,
                core_dumped: false,
            },
        };
        Self { kind }
    }

    /// Returns the cached terminal classification.
    #[must_use]
    pub const fn kind(&self) -> LinuxLeaderExitKindV1 {
        self.kind
    }

    /// Projects the terminal outcome to the legacy integer status.
    #[must_use]
    pub const fn legacy_exit_code(&self) -> i32 {
        match self.kind {
            LinuxLeaderExitKindV1::Exited { code } => code as i32,
            LinuxLeaderExitKindV1::Signaled { signal, .. } => 128 + signal,
        }
    }
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod tests;
