//! Native-only inherited qualification-ticket admission.

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
use runne_native_qualification::{MAX_FAULT_TICKET_BYTES, PendingQualificationFault};

pub(super) const QUALIFICATION_TICKET_DESCRIPTOR: RawFd = 198;
const QUALIFICATION_TICKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Closed setup failure with no descriptor, path, or input detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationTicketAdmissionError;

impl std::fmt::Display for QualificationTicketAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("qualification fault ticket admission rejected")
    }
}

impl std::error::Error for QualificationTicketAdmissionError {}
/// Unforgeable native proof that protected bundled discovery succeeded.
pub struct ProtectedQualificationTicketAdmission<'owner> {
    _owner: PhantomData<&'owner super::BundledRuntimeController>,
}
impl<'owner> ProtectedQualificationTicketAdmission<'owner> {
    pub(super) const fn from_protected_discovery(
        _owner: &'owner super::BundledRuntimeController,
    ) -> Self {
        Self {
            _owner: PhantomData,
        }
    }
}
struct InheritedQualificationTicketSlot {
    descriptor: Option<RawFd>,
}

impl InheritedQualificationTicketSlot {
    fn inspect() -> Result<Self, QualificationTicketAdmissionError> {
        Self::inspect_at(QUALIFICATION_TICKET_DESCRIPTOR)
    }

    fn inspect_at(descriptor: RawFd) -> Result<Self, QualificationTicketAdmissionError> {
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
            Err(_) => Err(QualificationTicketAdmissionError),
        }
    }

    const fn is_present(&self) -> bool {
        self.descriptor.is_some()
    }

    fn adopt_channel(
        mut self,
        timeout: Duration,
    ) -> Result<AdoptedQualificationTicket, QualificationTicketAdmissionError> {
        let descriptor = self
            .descriptor
            .take()
            .ok_or(QualificationTicketAdmissionError)?;
        let opened = OpenOptions::new()
            .read(true)
            .open(descriptor_path(descriptor));
        let closed = nix::unistd::close(OwnedRawDescriptor(descriptor));
        let file = opened.map_err(|_| QualificationTicketAdmissionError)?;
        closed.map_err(|_| QualificationTicketAdmissionError)?;
        validate_channel(&file)?;
        require_cloexec(&file)?;
        require_nonblocking(&file)?;
        Ok(AdoptedQualificationTicket {
            file,
            deadline: Instant::now() + timeout,
        })
    }

    #[cfg(test)]
    fn adopt_channel_for_test(
        self,
        timeout: Duration,
    ) -> Result<AdoptedQualificationTicket, QualificationTicketAdmissionError> {
        self.adopt_channel(timeout)
    }
}

impl Drop for InheritedQualificationTicketSlot {
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

struct AdoptedQualificationTicket {
    file: File,
    deadline: Instant,
}

impl AdoptedQualificationTicket {
    fn read_pending(
        mut self,
    ) -> Result<PendingQualificationFault, QualificationTicketAdmissionError> {
        let mut bytes = Vec::with_capacity(MAX_FAULT_TICKET_BYTES);
        let mut chunk = [0_u8; 1024];
        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(QualificationTicketAdmissionError)?;
            let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
            let mut descriptors = [PollFd::new(
                self.file.as_fd(),
                PollFlags::POLLIN | PollFlags::POLLHUP,
            )];
            if poll(&mut descriptors, timeout).map_err(|_| QualificationTicketAdmissionError)? == 0
            {
                return Err(QualificationTicketAdmissionError);
            }
            let events = descriptors[0].revents().unwrap_or(PollFlags::POLLNVAL);
            if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
                return Err(QualificationTicketAdmissionError);
            }
            let limit = (MAX_FAULT_TICKET_BYTES + 1 - bytes.len()).min(chunk.len());
            match self.file.read(&mut chunk[..limit]) {
                Ok(0) => break,
                Ok(count) => {
                    bytes.extend_from_slice(&chunk[..count]);
                    if bytes.len() > MAX_FAULT_TICKET_BYTES {
                        return Err(QualificationTicketAdmissionError);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(QualificationTicketAdmissionError),
            }
        }
        PendingQualificationFault::from_admitted_frame(bytes)
            .map_err(|_| QualificationTicketAdmissionError)
    }
}

/// Native host state containing at most one move-only pending ticket.
pub struct QualificationFaultHostState {
    pending: Mutex<Option<PendingQualificationFault>>,
}

impl QualificationFaultHostState {
    fn admit(
        slot: InheritedQualificationTicketSlot,
        protected_installed_admission: Option<ProtectedQualificationTicketAdmission<'_>>,
        timeout: Duration,
    ) -> Result<Self, QualificationTicketAdmissionError> {
        let pending = if slot.is_present() {
            protected_installed_admission.ok_or(QualificationTicketAdmissionError)?;
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
    ) -> Result<Option<PendingQualificationFault>, QualificationTicketAdmissionError> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| QualificationTicketAdmissionError)?
            .take())
    }

    #[cfg(test)]
    fn admit_for_test(
        slot: InheritedQualificationTicketSlot,
        protected_installed_admission: Option<ProtectedQualificationTicketAdmission<'_>>,
        timeout: Duration,
    ) -> Result<Self, QualificationTicketAdmissionError> {
        Self::admit(slot, protected_installed_admission, timeout)
    }

    #[cfg(test)]
    fn has_pending_for_test(&self) -> bool {
        self.pending.lock().is_ok_and(|pending| pending.is_some())
    }
}
pub fn admit_inherited_qualification_ticket(
    protected_installed_admission: Option<ProtectedQualificationTicketAdmission<'_>>,
) -> Result<QualificationFaultHostState, QualificationTicketAdmissionError> {
    QualificationFaultHostState::admit(
        InheritedQualificationTicketSlot::inspect()?,
        protected_installed_admission,
        QUALIFICATION_TICKET_TIMEOUT,
    )
}

#[cfg(test)]
const fn protected_admission_for_test() -> ProtectedQualificationTicketAdmission<'static> {
    ProtectedQualificationTicketAdmission {
        _owner: PhantomData,
    }
}

fn descriptor_path(descriptor: RawFd) -> String {
    format!("/dev/fd/{descriptor}")
}

fn validate_channel(file: &File) -> Result<(), QualificationTicketAdmissionError> {
    let file_type = file
        .metadata()
        .map_err(|_| QualificationTicketAdmissionError)?
        .file_type();
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| QualificationTicketAdmissionError)?,
    );
    if flags & OFlag::O_ACCMODE == OFlag::O_WRONLY {
        return Err(QualificationTicketAdmissionError);
    }
    if file_type.is_fifo() && flags & OFlag::O_ACCMODE == OFlag::O_RDONLY {
        return Ok(());
    }
    if file_type.is_socket() && getpeername::<UnixAddr>(file.as_raw_fd()).is_ok() {
        return Ok(());
    }
    Err(QualificationTicketAdmissionError)
}

fn require_cloexec(file: &File) -> Result<(), QualificationTicketAdmissionError> {
    let flags = FdFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFD).map_err(|_| QualificationTicketAdmissionError)?,
    ) | FdFlag::FD_CLOEXEC;
    fcntl(file, FcntlArg::F_SETFD(flags)).map_err(|_| QualificationTicketAdmissionError)?;
    let observed = FdFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFD).map_err(|_| QualificationTicketAdmissionError)?,
    );
    observed
        .contains(FdFlag::FD_CLOEXEC)
        .then_some(())
        .ok_or(QualificationTicketAdmissionError)
}

fn require_nonblocking(file: &File) -> Result<(), QualificationTicketAdmissionError> {
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| QualificationTicketAdmissionError)?,
    ) | OFlag::O_NONBLOCK;
    fcntl(file, FcntlArg::F_SETFL(flags)).map_err(|_| QualificationTicketAdmissionError)?;
    let observed = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| QualificationTicketAdmissionError)?,
    );
    observed
        .contains(OFlag::O_NONBLOCK)
        .then_some(())
        .ok_or(QualificationTicketAdmissionError)
}

#[cfg(test)]
fn inspect_qualification_ticket_at_for_test(
    descriptor: RawFd,
) -> Result<InheritedQualificationTicketSlot, QualificationTicketAdmissionError> {
    InheritedQualificationTicketSlot::inspect_at(descriptor)
}

#[cfg(test)]
#[path = "qualification_ticket_tests.rs"]
mod tests;
