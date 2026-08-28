use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;

use nix::fcntl::OFlag;
use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags, posix_spawn};
use nix::sys::stat::Mode;
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::UnixRetainedWriterProcess;

pub(super) fn spawn_macos_prepared_writer(
    spec: &VerifiedWriterLaunchSpec,
    transport: UnixStream,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    let executable = CString::new(spec.executable().as_os_str().as_bytes())
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let mode = CString::new(spec.arguments()[0]).map_err(|_| BrokerHandoffError::Rejected)?;
    let mut actions = PosixSpawnFileActions::init().map_err(|_| BrokerHandoffError::Unavailable)?;
    actions
        .add_dup2(transport.as_raw_fd(), libc::STDIN_FILENO)
        .and_then(|()| {
            (transport.as_raw_fd() == libc::STDIN_FILENO)
                .then_some(())
                .ok_or(nix::errno::Errno::EINVAL)
                .or_else(|_| actions.add_close(transport.as_raw_fd()))
        })
        .and_then(|()| {
            actions.add_open(
                libc::STDOUT_FILENO,
                "/dev/null",
                OFlag::O_WRONLY,
                Mode::empty(),
            )
        })
        .and_then(|()| {
            actions.add_open(
                libc::STDERR_FILENO,
                "/dev/null",
                OFlag::O_WRONLY,
                Mode::empty(),
            )
        })
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let mut attributes = PosixSpawnAttr::init().map_err(|_| BrokerHandoffError::Unavailable)?;
    attributes
        .set_flags(PosixSpawnFlags::from_bits_retain(
            libc::POSIX_SPAWN_CLOEXEC_DEFAULT as libc::c_int,
        ))
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    let arguments = [executable.as_c_str(), mode.as_c_str()];
    let environment: [&std::ffi::CStr; 0] = [];
    let spawned = posix_spawn(
        executable.as_c_str(),
        &actions,
        &attributes,
        &arguments,
        &environment,
    )
    .map_err(|_| BrokerHandoffError::Unavailable);
    drop(transport);
    let pid = spawned?;
    UnixRetainedWriterProcess::from_pid(pid)
}
