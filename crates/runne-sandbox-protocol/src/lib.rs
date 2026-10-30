#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Status-descriptor protocol shared by the runtime and the macOS sandbox
//! helper.
//!
//! The runtime creates a pipe, keeps the read end and passes the write end to
//! the helper, which arms that descriptor close-on-exec before doing any work
//! and reports through it:
//!
//! * [`STATUS_READY`] once the descriptor is armed;
//! * one exit-status byte when the helper fails before the target program
//!   starts.
//!
//! A successful `execv` closes the descriptor without a second byte, so the
//! runtime observes end-of-file right after the ready marker. The descriptor
//! never reaches the target program, so a program cannot fabricate either
//! signal: any other byte sequence is an unconfirmed report and must be
//! rejected instead of being turned into a program receipt.

/// Argument the runtime uses to pass the status descriptor number.
pub const STATUS_FD_FLAG: &str = "--status-fd";

/// Byte the helper writes once the status descriptor is armed.
pub const STATUS_READY: u8 = 1;

/// Exit status: the helper could not parse its invocation.
pub const STATUS_USAGE: u8 = 2;

/// Exit status: Seatbelt refused the generated profile.
pub const STATUS_SANDBOX: u8 = 3;

/// Exit status: the profile descriptor was unreadable or malformed.
pub const STATUS_PROFILE: u8 = 4;

/// Exit status: the working-directory descriptor was unusable.
pub const STATUS_CWD: u8 = 5;

/// Exit status: the resolved program could not be executed.
pub const STATUS_EXEC: u8 = 6;

/// Exit status: the helper aborted on a panic before starting the program.
pub const STATUS_PANIC: u8 = 10;

/// Error reported when the status descriptor never carried a complete report.
pub const PROTOCOL_ERROR: &str = "command_helper_protocol";

/// What the runtime observes on the status descriptor after the helper exits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Report {
    /// The helper armed the descriptor and the target program replaced it.
    Started,
    /// The helper failed before starting the target program.
    Failed(u8),
    /// The descriptor never carried a complete report.
    Unconfirmed,
}

/// Classifies the bytes read from the status descriptor.
///
/// Only a lone [`STATUS_READY`] proves that `execv` closed the descriptor, and
/// only the ready marker followed by exactly one known status byte proves a
/// helper failure. Everything else is [`Report::Unconfirmed`].
#[must_use]
pub const fn classify(bytes: &[u8]) -> Report {
    match bytes {
        [STATUS_READY] => Report::Started,
        [STATUS_READY, status] if error_for(*status).is_some() => Report::Failed(*status),
        _ => Report::Unconfirmed,
    }
}

/// Tool error returned for one helper status byte.
///
/// Callers must map an unknown byte to [`PROTOCOL_ERROR`], never to a program
/// receipt.
#[must_use]
pub const fn error_for(status: u8) -> Option<&'static str> {
    match status {
        STATUS_USAGE => Some("command_helper_usage"),
        STATUS_SANDBOX => Some("command_spawn_policy"),
        STATUS_PROFILE => Some("command_profile_denied"),
        STATUS_CWD => Some("command_cwd_denied"),
        STATUS_EXEC => Some("command_spawn_missing"),
        STATUS_PANIC => Some("command_helper_aborted"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lone_ready_marker_means_the_program_started() {
        assert_eq!(classify(&[STATUS_READY]), Report::Started);
    }

    #[test]
    fn a_ready_marker_followed_by_a_status_means_the_helper_failed() {
        assert_eq!(
            classify(&[STATUS_READY, STATUS_PROFILE]),
            Report::Failed(STATUS_PROFILE)
        );
    }

    #[test]
    fn incomplete_reports_are_unconfirmed() {
        for bytes in [
            Vec::new(),
            vec![STATUS_PROFILE],
            vec![STATUS_READY, STATUS_READY],
            vec![STATUS_READY, STATUS_PROFILE, STATUS_PROFILE],
        ] {
            assert_eq!(
                classify(&bytes),
                Report::Unconfirmed,
                "unexpected classification for {bytes:?}"
            );
        }
    }

    #[test]
    fn every_launch_status_maps_to_a_tool_error() {
        for (status, expected) in [
            (STATUS_USAGE, "command_helper_usage"),
            (STATUS_SANDBOX, "command_spawn_policy"),
            (STATUS_PROFILE, "command_profile_denied"),
            (STATUS_CWD, "command_cwd_denied"),
            (STATUS_EXEC, "command_spawn_missing"),
            (STATUS_PANIC, "command_helper_aborted"),
        ] {
            assert_eq!(error_for(status), Some(expected));
        }
    }

    #[test]
    fn unknown_statuses_have_no_tool_error() {
        assert_eq!(error_for(0), None);
        assert_eq!(error_for(STATUS_READY), None);
        assert_eq!(error_for(7), None);
        assert_eq!(error_for(u8::MAX), None);
    }
}
