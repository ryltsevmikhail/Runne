//! Fixed macOS inherited sealed-secret slot.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsFd as _, IntoRawFd, RawFd};
use std::os::unix::fs::FileTypeExt as _;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use runne_provider::CredentialSecretInputPresence;

use super::CliError;

const SECRET_INPUT_DESCRIPTOR: RawFd = 3;
#[cfg(not(feature = "local-native-enrollment-test"))]
const PRODUCTION_SECRET_INPUT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "local-native-enrollment-test")]
const LOCAL_SECRET_INPUT_TIMEOUT: Duration = Duration::from_secs(30);

/// Detected descriptor responsibility that remains unopened until after claim.
pub struct InheritedSecretInputSlot {
    descriptor: Option<RawFd>,
}

impl InheritedSecretInputSlot {
    /// Detects fd 3 without opening or reading it.
    pub fn inspect() -> Result<Self, CliError> {
        Self::inspect_at(SECRET_INPUT_DESCRIPTOR)
    }

    pub const fn presence(&self) -> CredentialSecretInputPresence {
        if self.descriptor.is_some() {
            CredentialSecretInputPresence::Present
        } else {
            CredentialSecretInputPresence::Absent
        }
    }

    /// Adopts fd 3 only after claim, validates a read-only pipe and closes the
    /// original inherited slot immediately after duplication.
    pub fn adopt(self) -> Result<InheritedSecretInput, CliError> {
        self.adopt_with_timeout(secret_input_timeout())
    }

    fn adopt_with_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<InheritedSecretInput, CliError> {
        let descriptor = self
            .descriptor
            .take()
            .ok_or(CliError::CredentialOperation)?;
        let opened = OpenOptions::new()
            .read(true)
            .open(descriptor_path(descriptor));
        let closed = nix::unistd::close(OwnedRawDescriptor(descriptor));
        let file = opened.map_err(|_| CliError::CredentialOperation)?;
        closed.map_err(|_| CliError::CredentialOperation)?;
        validate_read_pipe(&file)?;
        require_cloexec(&file)?;
        require_nonblocking(&file)?;
        Ok(InheritedSecretInput {
            file,
            deadline: Instant::now() + timeout,
        })
    }

    fn inspect_at(descriptor: RawFd) -> Result<Self, CliError> {
        match std::fs::metadata(descriptor_path(descriptor)) {
            Ok(_) => Ok(Self {
                descriptor: Some(descriptor),
            }),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::EBADF) =>
            {
                Ok(Self { descriptor: None })
            }
            Err(_) => Err(CliError::CredentialOperation),
        }
    }
}

const fn secret_input_timeout() -> Duration {
    #[cfg(feature = "local-native-enrollment-test")]
    {
        LOCAL_SECRET_INPUT_TIMEOUT
    }
    #[cfg(not(feature = "local-native-enrollment-test"))]
    PRODUCTION_SECRET_INPUT_TIMEOUT
}

/// Read-only adopted pipe with one fixed whole-envelope deadline.
pub struct InheritedSecretInput {
    file: File,
    deadline: Instant,
}

impl Read for InheritedSecretInput {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(read_timeout)?;
            let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
            let mut descriptors = [PollFd::new(self.file.as_fd(), PollFlags::POLLIN)];
            let ready = poll(&mut descriptors, timeout).map_err(std::io::Error::other)?;
            if ready == 0 {
                return Err(read_timeout());
            }
            let events = descriptors[0].revents().unwrap_or(PollFlags::POLLNVAL);
            if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
                return Err(std::io::Error::other("invalid sealed-secret pipe"));
            }
            match self.file.read(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }
}

fn read_timeout() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "sealed-secret pipe deadline elapsed",
    )
}

impl Drop for InheritedSecretInputSlot {
    fn drop(&mut self) {
        if let Some(descriptor) = self.descriptor.take() {
            let _ = nix::unistd::close(OwnedRawDescriptor(descriptor));
        }
    }
}

struct OwnedRawDescriptor(RawFd);

impl IntoRawFd for OwnedRawDescriptor {
    fn into_raw_fd(self) -> RawFd {
        self.0
    }
}

fn descriptor_path(descriptor: RawFd) -> String {
    format!("/dev/fd/{descriptor}")
}

fn validate_read_pipe(file: &File) -> Result<(), CliError> {
    if !file
        .metadata()
        .map_err(|_| CliError::CredentialOperation)?
        .file_type()
        .is_fifo()
    {
        return Err(CliError::CredentialOperation);
    }
    let flags = fcntl(file, FcntlArg::F_GETFL).map_err(|_| CliError::CredentialOperation)?;
    if OFlag::from_bits_retain(flags) & OFlag::O_ACCMODE != OFlag::O_RDONLY {
        return Err(CliError::CredentialOperation);
    }
    Ok(())
}

fn require_cloexec(file: &File) -> Result<(), CliError> {
    let current = fcntl(file, FcntlArg::F_GETFD).map_err(|_| CliError::CredentialOperation)?;
    let flags = FdFlag::from_bits_retain(current) | FdFlag::FD_CLOEXEC;
    fcntl(file, FcntlArg::F_SETFD(flags)).map_err(|_| CliError::CredentialOperation)?;
    let verified = fcntl(file, FcntlArg::F_GETFD).map_err(|_| CliError::CredentialOperation)?;
    if FdFlag::from_bits_retain(verified).contains(FdFlag::FD_CLOEXEC) {
        Ok(())
    } else {
        Err(CliError::CredentialOperation)
    }
}

fn require_nonblocking(file: &File) -> Result<(), CliError> {
    let current = fcntl(file, FcntlArg::F_GETFL).map_err(|_| CliError::CredentialOperation)?;
    let flags = OFlag::from_bits_retain(current) | OFlag::O_NONBLOCK;
    fcntl(file, FcntlArg::F_SETFL(flags)).map_err(|_| CliError::CredentialOperation)?;
    let verified = fcntl(file, FcntlArg::F_GETFL).map_err(|_| CliError::CredentialOperation)?;
    OFlag::from_bits_retain(verified)
        .contains(OFlag::O_NONBLOCK)
        .then_some(())
        .ok_or(CliError::CredentialOperation)
}

#[cfg(test)]
pub fn inspect_secret_input_at_for_test(
    descriptor: RawFd,
) -> Result<InheritedSecretInputSlot, CliError> {
    InheritedSecretInputSlot::inspect_at(descriptor)
}

#[cfg(test)]
impl InheritedSecretInputSlot {
    pub const fn descriptor_for_test(&self) -> RawFd {
        match self.descriptor {
            Some(descriptor) => descriptor,
            None => -1,
        }
    }

    pub fn adopt_with_timeout_for_test(
        self,
        timeout: Duration,
    ) -> Result<InheritedSecretInput, CliError> {
        self.adopt_with_timeout(timeout)
    }
}

#[cfg(test)]
pub fn secret_input_has_cloexec_for_test(input: &InheritedSecretInput) -> bool {
    fcntl(&input.file, FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_retain)
        .is_ok_and(|flags| flags.contains(FdFlag::FD_CLOEXEC))
}

#[cfg(test)]
pub fn secret_input_is_nonblocking_for_test(input: &InheritedSecretInput) -> bool {
    fcntl(&input.file, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_retain)
        .is_ok_and(|flags| flags.contains(OFlag::O_NONBLOCK))
}
