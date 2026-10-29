//! Process-group area identity, termination and emptiness proof.
#![allow(unsafe_code)]

use super::error::MacOsCommandError as CommandError;
use std::time::{Duration, Instant};

/// Identity of one admitted macOS process group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacOsAreaIdentity {
    bytes: [u8; 100],
}

impl MacOsAreaIdentity {
    pub(super) const fn from_bytes(bytes: [u8; 100]) -> Self {
        Self { bytes }
    }

    /// Fixed-size non-secret identity used by store facts.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 100] {
        self.bytes
    }
}

/// One live or reaped process group owned by this invocation.
pub struct MacOsManagedArea {
    pgid: i32,
    identity: MacOsAreaIdentity,
}

/// Proof that `kill(-pgid, 0)` observed no remaining member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedEmptyMacOsArea {
    identity: MacOsAreaIdentity,
}

impl VerifiedEmptyMacOsArea {
    /// Identity that was proven empty.
    #[must_use]
    pub const fn identity(&self) -> MacOsAreaIdentity {
        self.identity
    }
}

impl MacOsManagedArea {
    pub(super) const fn new(pgid: i32, identity: MacOsAreaIdentity) -> Self {
        Self { pgid, identity }
    }

    /// Identity for durable permission facts.
    #[must_use]
    pub const fn identity(&self) -> MacOsAreaIdentity {
        self.identity
    }

    /// Sends `SIGKILL` to every member of this group.
    pub fn terminate(&self) {
        unsafe {
            libc::kill(-self.pgid, libc::SIGKILL);
        }
    }

    /// Waits until the kernel reports no member of this process group.
    ///
    /// # Errors
    /// Returns timeout when a member survives the bounded interval.
    pub fn prove_empty(&self, timeout: Duration) -> Result<VerifiedEmptyMacOsArea, CommandError> {
        let deadline = Instant::now() + timeout;
        loop {
            let result = unsafe { libc::kill(-self.pgid, 0) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(VerifiedEmptyMacOsArea {
                        identity: self.identity,
                    });
                }
                if error.raw_os_error() != Some(libc::EPERM) {
                    return Err(CommandError::Area);
                }
            }
            if Instant::now() >= deadline {
                return Err(CommandError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
