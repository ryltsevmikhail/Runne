use super::ManagedAreaIdentity;
use rustix::fs::{AtFlags, Mode, OFlags, fstat, fstatfs, openat, unlinkat};
use rustix::process::Signal;
use std::fs::File;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod members;

/// Closed managed-area operation failures. No native path or OS error is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagedAreaError {
    /// Host cgroup authority or a required kernel interface is unavailable.
    #[error("managed process area unavailable")]
    Unavailable,
    /// The identity bytes or binding are malformed.
    #[error("managed process area identity is invalid")]
    InvalidIdentity,
    /// The deterministic area name is already occupied.
    #[error("managed process area already exists")]
    Conflict,
    /// The area or terminal evidence could not be proven exact.
    #[error("managed process area is unverified")]
    Unverified,
    /// A requested wait is outside the bounded policy.
    #[error("managed process area timeout is invalid")]
    InvalidTimeout,
}

/// Held descriptor for one exact TaskRun cgroup area.
pub struct LinuxManagedArea {
    root: Arc<File>,
    directory: File,
    name: String,
    identity: ManagedAreaIdentity,
}

impl LinuxManagedArea {
    pub(super) fn new(
        root: Arc<File>,
        directory: File,
        name: String,
        identity: ManagedAreaIdentity,
    ) -> Self {
        Self {
            root,
            directory,
            name,
            identity,
        }
    }

    /// Returns the exact persistable identity for restart recovery.
    #[must_use]
    pub fn identity(&self) -> &ManagedAreaIdentity {
        &self.identity
    }

    /// Attaches a caller-owned, unreaped child while it is stopped at a gate.
    /// The caller must own the unreaped child and release it only after success.
    /// Stopped state alone is not ownership proof; this does not prevent migration.
    pub fn attach_gated_process(&self, pid: u32) -> Result<(), ManagedAreaError> {
        if pid == 0
            || pid > i32::MAX as u32
            || self.is_populated()?
            || !members::process_is_stopped(pid)?
        {
            return Err(ManagedAreaError::Unverified);
        }
        members::write_control(&self.directory, "cgroup.procs", &format!("{pid}\n"))?;
        if !members::read_pids(&self.directory)?.contains(&pid) {
            return Err(ManagedAreaError::Unverified);
        }
        Ok(())
    }

    /// Sends bounded best-effort TERM, then exact-area cgroup.kill.
    /// Success requires recursive `cgroup.events` evidence of `populated 0`.
    pub fn terminate(&self, grace: Duration) -> Result<(), ManagedAreaError> {
        if grace > Duration::from_secs(30) {
            return Err(ManagedAreaError::InvalidTimeout);
        }
        self.verify_identity()?;
        let deadline = Instant::now() + grace;
        let _ = members::signal_current_members(&self.directory, Signal::TERM, deadline);
        if self.wait_empty_until(deadline)? {
            return Ok(());
        }
        self.verify_identity()?;
        members::write_control(&self.directory, "cgroup.kill", "1\n")?;
        if self.wait_empty(Duration::from_secs(3))? {
            Ok(())
        } else {
            Err(ManagedAreaError::Unverified)
        }
    }

    /// Removes an already empty area after held-FD and current-name identity validation.
    /// The root must have one exclusive writer; cgroupfs offers no compare-and-unlink.
    pub fn remove_empty(self) -> Result<(), ManagedAreaError> {
        self.verify_identity()?;
        self.require_empty()?;
        let current = openat(
            self.root.as_ref(),
            self.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ManagedAreaError::Unverified)?;
        let stat = fstat(&current).map_err(|_| ManagedAreaError::Unverified)?;
        if stat.st_dev != self.identity.area_device || stat.st_ino != self.identity.area_inode {
            return Err(ManagedAreaError::Unverified);
        }
        unlinkat(self.root.as_ref(), self.name.as_str(), AtFlags::REMOVEDIR)
            .map_err(|_| ManagedAreaError::Unverified)
    }

    /// Reads recursive population evidence for this exact area.
    pub fn is_populated(&self) -> Result<bool, ManagedAreaError> {
        self.verify_identity()?;
        members::is_populated(&self.directory)
    }

    /// Mints a move-only proof tied to this held area after recursive-empty verification.
    pub fn prove_empty(&self) -> Result<VerifiedEmptyManagedArea<'_>, ManagedAreaError> {
        self.require_empty()?;
        Ok(VerifiedEmptyManagedArea {
            area: self,
            identity: self.identity.to_bytes(),
        })
    }

    pub(super) fn require_empty(&self) -> Result<(), ManagedAreaError> {
        self.is_populated()?
            .then_some(())
            .map_or(Ok(()), |_| Err(ManagedAreaError::Conflict))
    }

    fn verify_identity(&self) -> Result<(), ManagedAreaError> {
        let stat = fstat(&self.directory).map_err(|_| ManagedAreaError::Unavailable)?;
        if stat.st_dev != self.identity.area_device || stat.st_ino != self.identity.area_inode {
            return Err(ManagedAreaError::Unverified);
        }
        if fstatfs(&self.directory)
            .map_err(|_| ManagedAreaError::Unavailable)?
            .f_type
            != 0x6367_7270
        {
            return Err(ManagedAreaError::Unverified);
        }
        let current = openat(
            self.root.as_ref(),
            self.name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| ManagedAreaError::Unverified)?;
        let named = fstat(&current).map_err(|_| ManagedAreaError::Unverified)?;
        if named.st_dev != self.identity.area_device || named.st_ino != self.identity.area_inode {
            return Err(ManagedAreaError::Unverified);
        }
        Ok(())
    }

    fn wait_empty(&self, timeout: Duration) -> Result<bool, ManagedAreaError> {
        self.wait_empty_until(Instant::now() + timeout)
    }

    fn wait_empty_until(&self, deadline: Instant) -> Result<bool, ManagedAreaError> {
        loop {
            self.verify_identity()?;
            if !members::is_populated(&self.directory)? {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10).min(remaining));
        }
    }
}

/// Non-forgeable safe-code evidence that one exact managed area was empty.
///
/// The private field and constructor keep callers from turning an identity
/// byte array into a process-stop proof without the held-FD kernel check.
pub struct VerifiedEmptyManagedArea<'area> {
    area: &'area LinuxManagedArea,
    identity: [u8; 100],
}

impl VerifiedEmptyManagedArea<'_> {
    /// Returns the exact identity checked while minting this proof.
    #[must_use]
    pub const fn identity_bytes(&self) -> &[u8; 100] {
        &self.identity
    }

    /// Rechecks the held descriptor immediately before the durable state change.
    pub fn revalidate(&self) -> Result<(), ManagedAreaError> {
        if self.area.identity.to_bytes() != self.identity {
            return Err(ManagedAreaError::Unverified);
        }
        self.area.require_empty()
    }
}
