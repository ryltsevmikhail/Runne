//! Native-only inherited qualification-admission bundle input.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::marker::PhantomData;
use std::os::fd::{AsFd as _, AsRawFd as _, IntoRawFd, RawFd};
use std::os::unix::fs::FileTypeExt as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{UnixAddr, getpeername};
use runne_native_qualification::{MAX_ADMISSION_BUNDLE_BYTES, PendingQualificationAdmission};

pub(super) const QUALIFICATION_ADMISSION_DESCRIPTOR: RawFd = 198;
const QUALIFICATION_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Closed setup failure with no descriptor, path, or input detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionHostError;

impl std::fmt::Display for QualificationAdmissionHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("qualification admission bundle rejected")
    }
}

impl std::error::Error for QualificationAdmissionHostError {}
/// Unforgeable native proof that protected bundled discovery succeeded.
pub struct ProtectedQualificationAdmission<'owner> {
    _owner: PhantomData<&'owner super::BundledRuntimeController>,
}
impl<'owner> ProtectedQualificationAdmission<'owner> {
    pub(super) const fn from_protected_discovery(
        _owner: &'owner super::BundledRuntimeController,
    ) -> Self {
        Self {
            _owner: PhantomData,
        }
    }
}
struct InheritedQualificationAdmissionSlot {
    descriptor: Option<RawFd>,
}

impl InheritedQualificationAdmissionSlot {
    fn inspect() -> Result<Self, QualificationAdmissionHostError> {
        Self::inspect_at(QUALIFICATION_ADMISSION_DESCRIPTOR)
    }

    fn inspect_at(descriptor: RawFd) -> Result<Self, QualificationAdmissionHostError> {
        match std::fs::metadata(descriptor_path(descriptor)) {
            Ok(_) => Ok(Self {
                descriptor: Some(descriptor),
            }),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(nix::libc::EBADF) =>
            {
                Ok(Self { descriptor: None })
            }
            Err(_) => Err(QualificationAdmissionHostError),
        }
    }

    const fn is_present(&self) -> bool {
        self.descriptor.is_some()
    }

    fn adopt_channel(
        mut self,
        timeout: Duration,
    ) -> Result<AdoptedQualificationAdmission, QualificationAdmissionHostError> {
        let descriptor = self
            .descriptor
            .take()
            .ok_or(QualificationAdmissionHostError)?;
        let opened = OpenOptions::new()
            .read(true)
            .open(descriptor_path(descriptor));
        let closed = nix::unistd::close(OwnedRawDescriptor(descriptor));
        let file = opened.map_err(|_| QualificationAdmissionHostError)?;
        closed.map_err(|_| QualificationAdmissionHostError)?;
        validate_channel(&file)?;
        require_cloexec(&file)?;
        require_nonblocking(&file)?;
        Ok(AdoptedQualificationAdmission {
            file,
            deadline: Instant::now() + timeout,
        })
    }

    #[cfg(test)]
    fn adopt_channel_for_test(
        self,
        timeout: Duration,
    ) -> Result<AdoptedQualificationAdmission, QualificationAdmissionHostError> {
        self.adopt_channel(timeout)
    }
}

impl Drop for InheritedQualificationAdmissionSlot {
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

struct AdoptedQualificationAdmission {
    file: File,
    deadline: Instant,
}

impl AdoptedQualificationAdmission {
    fn read_pending(
        mut self,
    ) -> Result<PendingQualificationAdmission, QualificationAdmissionHostError> {
        let mut bytes = Vec::with_capacity(MAX_ADMISSION_BUNDLE_BYTES);
        let mut chunk = [0_u8; 1024];
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(QualificationAdmissionHostError)?;
            let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
            let mut descriptors = [PollFd::new(
                self.file.as_fd(),
                PollFlags::POLLIN | PollFlags::POLLHUP,
            )];
            if poll(&mut descriptors, timeout).map_err(|_| QualificationAdmissionHostError)? == 0 {
                return Err(QualificationAdmissionHostError);
            }
            let events = descriptors[0].revents().unwrap_or(PollFlags::POLLNVAL);
            if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
                return Err(QualificationAdmissionHostError);
            }
            let limit = (MAX_ADMISSION_BUNDLE_BYTES + 1 - bytes.len()).min(chunk.len());
            match self.file.read(&mut chunk[..limit]) {
                Ok(0) => break,
                Ok(count) => {
                    bytes.extend_from_slice(&chunk[..count]);
                    if bytes.len() > MAX_ADMISSION_BUNDLE_BYTES {
                        return Err(QualificationAdmissionHostError);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(QualificationAdmissionHostError),
            }
        }
        PendingQualificationAdmission::from_admitted_bundle(bytes)
            .map_err(|_| QualificationAdmissionHostError)
    }
}

/// Native host state containing at most one move-only pending admission.
pub struct QualificationAdmissionHostState {
    pending: Mutex<Option<PendingQualificationAdmission>>,
}

impl QualificationAdmissionHostState {
    fn admit(
        slot: InheritedQualificationAdmissionSlot,
        protected_installed_admission: Option<ProtectedQualificationAdmission<'_>>,
        timeout: Duration,
    ) -> Result<Self, QualificationAdmissionHostError> {
        let pending = if slot.is_present() {
            protected_installed_admission.ok_or(QualificationAdmissionHostError)?;
            Some(slot.adopt_channel(timeout)?.read_pending()?)
        } else {
            None
        };
        Ok(Self {
            pending: Mutex::new(pending),
        })
    }

    pub(crate) fn take_pending_for_relay(
        &self,
    ) -> Result<Option<PendingQualificationAdmission>, QualificationAdmissionHostError> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| QualificationAdmissionHostError)?
            .take())
    }

    #[cfg(test)]
    fn admit_for_test(
        slot: InheritedQualificationAdmissionSlot,
        protected_installed_admission: Option<ProtectedQualificationAdmission<'_>>,
        timeout: Duration,
    ) -> Result<Self, QualificationAdmissionHostError> {
        Self::admit(slot, protected_installed_admission, timeout)
    }

    #[cfg(test)]
    fn has_pending_for_test(&self) -> bool {
        self.pending.lock().is_ok_and(|pending| pending.is_some())
    }
}
pub fn admit_inherited_qualification_admission(
    protected_installed_admission: Option<ProtectedQualificationAdmission<'_>>,
) -> Result<QualificationAdmissionHostState, QualificationAdmissionHostError> {
    QualificationAdmissionHostState::admit(
        InheritedQualificationAdmissionSlot::inspect()?,
        protected_installed_admission,
        QUALIFICATION_ADMISSION_TIMEOUT,
    )
}

#[cfg(test)]
const fn protected_admission_for_test() -> ProtectedQualificationAdmission<'static> {
    ProtectedQualificationAdmission {
        _owner: PhantomData,
    }
}

fn descriptor_path(descriptor: RawFd) -> String {
    format!("/dev/fd/{descriptor}")
}

fn validate_channel(file: &File) -> Result<(), QualificationAdmissionHostError> {
    let file_type = file
        .metadata()
        .map_err(|_| QualificationAdmissionHostError)?
        .file_type();
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| QualificationAdmissionHostError)?,
    );
    if flags & OFlag::O_ACCMODE == OFlag::O_WRONLY {
        return Err(QualificationAdmissionHostError);
    }
    if file_type.is_fifo() && flags & OFlag::O_ACCMODE == OFlag::O_RDONLY {
        return Ok(());
    }
    if file_type.is_socket() && getpeername::<UnixAddr>(file.as_raw_fd()).is_ok() {
        return Ok(());
    }
    Err(QualificationAdmissionHostError)
}

fn require_cloexec(file: &File) -> Result<(), QualificationAdmissionHostError> {
    let flags = FdFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFD).map_err(|_| QualificationAdmissionHostError)?,
    ) | FdFlag::FD_CLOEXEC;
    fcntl(file, FcntlArg::F_SETFD(flags)).map_err(|_| QualificationAdmissionHostError)?;
    let observed = FdFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFD).map_err(|_| QualificationAdmissionHostError)?,
    );
    observed
        .contains(FdFlag::FD_CLOEXEC)
        .then_some(())
        .ok_or(QualificationAdmissionHostError)
}

fn require_nonblocking(file: &File) -> Result<(), QualificationAdmissionHostError> {
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| QualificationAdmissionHostError)?,
    ) | OFlag::O_NONBLOCK;
    fcntl(file, FcntlArg::F_SETFL(flags)).map_err(|_| QualificationAdmissionHostError)?;
    let observed = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| QualificationAdmissionHostError)?,
    );
    observed
        .contains(OFlag::O_NONBLOCK)
        .then_some(())
        .ok_or(QualificationAdmissionHostError)
}

#[cfg(test)]
fn inspect_qualification_admission_at_for_test(
    descriptor: RawFd,
) -> Result<InheritedQualificationAdmissionSlot, QualificationAdmissionHostError> {
    InheritedQualificationAdmissionSlot::inspect_at(descriptor)
}

#[cfg(test)]
#[path = "qualification_ticket_tests.rs"]
mod tests;
