//! Failure reporting through the descriptor inherited from the runtime.

use std::ffi::OsString;
use std::os::fd::RawFd;

use runne_sandbox_protocol::{STATUS_FD_FLAG, STATUS_PANIC, STATUS_READY};

/// Write end of the status descriptor owned by the runtime.
#[derive(Clone, Copy, Debug)]
pub struct Reporter {
    fd: RawFd,
}

impl Reporter {
    /// Binds and arms the descriptor the runtime passed, if it passed one.
    ///
    /// The descriptor is marked close-on-exec before any other helper work, so
    /// a later `execv` closes it and the runtime observes end-of-file.
    #[must_use]
    pub fn from_arguments(arguments: &[OsString]) -> Option<Self> {
        let fd = status_descriptor(arguments)?;
        if set_close_on_exec(fd).is_err() {
            return None;
        }
        let reporter = Self { fd };
        write_byte(fd, STATUS_READY).then_some(reporter)
    }

    /// Reports the status of a path that never reached the target program.
    pub fn fail(self, status: u8) {
        let _ = write_byte(self.fd, status);
    }

    /// Reports panics instead of exiting without a status byte.
    ///
    /// The previous hook still runs, so the panic message keeps reaching
    /// stderr while the runtime also learns the helper never started the
    /// program.
    pub fn report_panics(self) {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = write_byte(self.fd, STATUS_PANIC);
            previous(info);
        }));
    }

    /// Descriptor the helper keeps open until `execv` replaces the process.
    #[must_use]
    pub const fn descriptor(self) -> RawFd {
        self.fd
    }
}

/// Finds the descriptor number the runtime passed on the command line.
///
/// This scan is deliberately tolerant: the strict argument parser reports a
/// malformed flag separately, and it can only do so after the reporter has
/// armed the descriptor.
fn status_descriptor(arguments: &[OsString]) -> Option<RawFd> {
    let flag = OsString::from(STATUS_FD_FLAG);
    let position = arguments.iter().position(|argument| *argument == flag)?;
    let value = arguments.get(position.saturating_add(1))?.to_str()?;
    let fd: RawFd = value.parse().ok()?;
    (fd >= 3).then_some(fd)
}

fn set_close_on_exec(fd: RawFd) -> Result<(), ()> {
    // SAFETY: F_GETFD and F_SETFD only inspect and update this descriptor's
    // flags; both calls are made on a descriptor the runtime opened.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(());
    }
    // SAFETY: same as above; the flag word is only modified bitwise.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, current | libc::FD_CLOEXEC) } < 0 {
        return Err(());
    }
    Ok(())
}

/// Writes one status byte; a single-byte write to a pipe never blocks.
fn write_byte(fd: RawFd, byte: u8) -> bool {
    let pointer = std::ptr::from_ref(&byte).cast();
    // SAFETY: `fd` is the status pipe write end and `pointer` covers one
    // initialized byte for the duration of the call.
    unsafe { libc::write(fd, pointer, 1) == 1 }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use runne_sandbox_protocol::STATUS_PROFILE;

    use super::*;

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [0; 2];
        // SAFETY: the array holds exactly the two descriptors `pipe` fills.
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        // SAFETY: `pipe` returned two owned descriptors.
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn arguments(fd: RawFd) -> Vec<OsString> {
        vec![
            OsString::from(STATUS_FD_FLAG),
            OsString::from(fd.to_string()),
        ]
    }

    fn read_report(writer: OwnedFd, reader: OwnedFd) -> Vec<u8> {
        drop(writer);
        let mut file = File::from(reader);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read status report");
        bytes
    }

    #[test]
    fn arms_the_descriptor_and_reports_the_ready_marker() {
        let (reader, writer) = pipe();
        let fd = writer.as_raw_fd();
        let reporter = Reporter::from_arguments(&arguments(fd)).expect("armed reporter");
        assert_eq!(reporter.descriptor(), fd);
        // SAFETY: F_GETFD only inspects this descriptor's flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "descriptor is not close-on-exec"
        );
        assert_eq!(read_report(writer, reader), vec![STATUS_READY]);
    }

    #[test]
    fn reports_a_failure_after_the_ready_marker() {
        let (reader, writer) = pipe();
        let reporter = Reporter::from_arguments(&arguments(writer.as_raw_fd())).expect("armed");
        reporter.fail(STATUS_PROFILE);
        assert_eq!(
            read_report(writer, reader),
            vec![STATUS_READY, STATUS_PROFILE]
        );
    }

    #[test]
    fn ignores_an_invocation_without_a_descriptor() {
        let invocation = vec![OsString::from("--self-test")];
        assert!(Reporter::from_arguments(&invocation).is_none());
    }

    #[test]
    fn rejects_standard_descriptors_and_malformed_values() {
        for value in ["2", "1", "not-a-number", "-5"] {
            let invocation = vec![OsString::from(STATUS_FD_FLAG), OsString::from(value)];
            assert!(
                Reporter::from_arguments(&invocation).is_none(),
                "descriptor {value} was accepted"
            );
        }
    }
}
