use std::ffi::CString;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;

use nix::fcntl::OFlag;
use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags, posix_spawn};
use nix::sys::stat::Mode;
use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::{
    UnixRetainedWriterProcess,
    macos_secret_pipe::{MacOsPairSecretWriter, PreparedMacOsPairSecretPipe},
    macos_writer_admission::RetainedMacOsWriterImage,
};

pub(super) fn spawn_macos_prepared_writer(
    spec: &VerifiedWriterLaunchSpec,
    image: &RetainedMacOsWriterImage,
    transport: UnixStream,
    pair_secret: Option<PreparedMacOsPairSecretPipe>,
) -> Result<(UnixRetainedWriterProcess, Option<MacOsPairSecretWriter>), BrokerHandoffError> {
    let executable = CString::new(image.path().as_os_str().as_bytes())
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let mode = CString::new(spec.arguments()[0]).map_err(|_| BrokerHandoffError::Rejected)?;
    let bootstrap = duplicate_above_reserved(&transport)?;
    let (secret_reader, secret_writer) = pair_secret.map_or((None, None), |pipe| {
        let (reader, writer) = pipe.into_parts();
        (Some(reader), Some(writer))
    });
    let secret_reader = secret_reader
        .as_ref()
        .map(duplicate_above_reserved)
        .transpose()?;
    let mut actions = PosixSpawnFileActions::init().map_err(|_| BrokerHandoffError::Unavailable)?;
    actions
        .add_dup2(bootstrap.as_raw_fd(), libc::STDIN_FILENO)
        .and_then(|()| actions.add_close(bootstrap.as_raw_fd()))
        .and_then(|()| match secret_reader.as_ref() {
            Some(secret) => actions
                .add_dup2(secret.as_raw_fd(), 3)
                .and_then(|()| actions.add_close(secret.as_raw_fd())),
            None => actions.add_close(3),
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
    UnixRetainedWriterProcess::from_pid(pid).map(|process| (process, secret_writer))
}

fn duplicate_above_reserved(
    descriptor: &impl std::os::fd::AsFd,
) -> Result<OwnedFd, BrokerHandoffError> {
    rustix::io::fcntl_dupfd_cloexec(descriptor, 4).map_err(|_| BrokerHandoffError::Unavailable)
}
