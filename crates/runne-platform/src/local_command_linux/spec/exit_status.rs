use super::LinuxCommandError;

/// Read-only outcome data from this handle's successful wait of its Linux command leader.
/// It reports leader termination only; it does not prove area emptiness or authorize effects.
#[derive(Debug, PartialEq, Eq)]
pub struct LinuxLeaderExitObservationV1 {
    kind: LinuxLeaderExitKindV1,
}

/// Copyable classification data for a Linux command leader's terminal outcome.
/// This data alone grants no execution or effect authority and does not prove area emptiness.
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

impl LinuxLeaderExitObservationV1 {
    /// Returns the cached terminal classification.
    #[must_use]
    pub const fn kind(&self) -> LinuxLeaderExitKindV1 {
        self.kind
    }

    /// Projects the terminal outcome to the command API's legacy integer status.
    #[must_use]
    pub const fn legacy_exit_code(&self) -> i32 {
        match self.kind {
            LinuxLeaderExitKindV1::Exited { code } => code as i32,
            LinuxLeaderExitKindV1::Signaled { signal, .. } => 128 + signal,
        }
    }

    pub(super) fn decode_wait_status(status: i32) -> Result<Self, LinuxCommandError> {
        if libc::WIFEXITED(status) {
            Ok(Self {
                kind: LinuxLeaderExitKindV1::Exited {
                    code: libc::WEXITSTATUS(status) as u8,
                },
            })
        } else if libc::WIFSIGNALED(status) {
            Ok(Self {
                kind: LinuxLeaderExitKindV1::Signaled {
                    signal: libc::WTERMSIG(status),
                    core_dumped: libc::WCOREDUMP(status),
                },
            })
        } else {
            Err(LinuxCommandError::Unverified)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxCommandError, LinuxLeaderExitKindV1, LinuxLeaderExitObservationV1};

    fn exited_status(code: u8) -> i32 {
        i32::from(code) << 8
    }

    fn signaled_status(signal: i32, core_dumped: bool) -> i32 {
        signal | if core_dumped { 0x80 } else { 0 }
    }

    #[test]
    fn normal_exit_codes_preserve_the_legacy_projection() {
        for code in [0, 1, 137, 255] {
            let observation = LinuxLeaderExitObservationV1::decode_wait_status(exited_status(code))
                .expect("valid exit status");
            assert_eq!(observation.kind(), LinuxLeaderExitKindV1::Exited { code });
            assert_eq!(observation.legacy_exit_code(), i32::from(code));
        }
    }

    #[test]
    fn signal_exit_codes_and_core_flag_are_classified() {
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            let observation =
                LinuxLeaderExitObservationV1::decode_wait_status(signaled_status(signal, false))
                    .expect("valid signal status");
            assert_eq!(
                observation.kind(),
                LinuxLeaderExitKindV1::Signaled {
                    signal,
                    core_dumped: false
                }
            );
            assert_eq!(observation.legacy_exit_code(), 128 + signal);
        }
        let core =
            LinuxLeaderExitObservationV1::decode_wait_status(signaled_status(libc::SIGABRT, true))
                .expect("valid core status");
        assert_eq!(
            core.kind(),
            LinuxLeaderExitKindV1::Signaled {
                signal: libc::SIGABRT,
                core_dumped: true
            }
        );
        assert_eq!(core.legacy_exit_code(), 128 + libc::SIGABRT);
    }

    #[test]
    fn stopped_and_continued_statuses_are_not_terminal_observations() {
        let stopped = (libc::SIGSTOP << 8) | 0x7f;
        assert_eq!(
            LinuxLeaderExitObservationV1::decode_wait_status(stopped).unwrap_err(),
            LinuxCommandError::Unverified
        );
        assert_eq!(
            LinuxLeaderExitObservationV1::decode_wait_status(0xffff).unwrap_err(),
            LinuxCommandError::Unverified
        );
    }
}
