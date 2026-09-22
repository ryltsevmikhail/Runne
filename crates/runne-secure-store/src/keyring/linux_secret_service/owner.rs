//! Owner resolution and validation for the Secret Service unique-name binding.
//!
//! DESIGN v6 §4-P4/F5: before any Secret Service operation the current owner
//! of `org.freedesktop.secrets` is resolved (`GetNameOwner`; missing name is
//! fail-closed, no activation), validated (peer uid == our effective uid,
//! executable canonical under `/usr/bin`, root-owned, no group/world write),
//! and every subsequent operation of the same bound session is addressed to
//! that unique name. Owner loss or change fails closed without retry.
//! `/proc` facts are injected so validation logic is deterministically
//! testable without touching a real service process.

use std::path::{Path, PathBuf};

/// Injected process facts source (production: `/proc`).
pub trait ProcessFacts {
    fn effective_uid(&self) -> u32;
    /// Canonical executable path of one pid.
    fn executable_path(&self, pid: u32) -> Result<PathBuf, OwnerError>;
    /// Owner uid and permission bits of one executable path.
    fn executable_metadata(&self, path: &Path) -> Result<ExecutableFacts, OwnerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableFacts {
    pub uid: u32,
    pub mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    /// Peer process facts unreadable (exited or hidden).
    Unreadable,
    /// Validation failed (uid mismatch, bad path prefix, bad ownership).
    Invalid,
}

/// Validated binding to the resolved unique-name owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerBinding {
    pub unique_name: String,
    pub pid: u32,
    pub uid: u32,
    pub executable: PathBuf,
}

impl OwnerBinding {
    /// Resolves and validates the owner behind one unique name.
    pub fn validate(
        facts: &dyn ProcessFacts,
        unique_name: String,
        peer: super::port::PeerCredentials,
    ) -> Result<Self, OwnerError> {
        if !unique_name.starts_with(':') {
            return Err(OwnerError::Invalid);
        }
        if peer.uid != facts.effective_uid() {
            return Err(OwnerError::Invalid);
        }
        let executable = facts.executable_path(peer.pid)?;
        if !executable.starts_with("/usr/bin/") || !executable.is_absolute() {
            return Err(OwnerError::Invalid);
        }
        let metadata = facts.executable_metadata(&executable)?;
        if metadata.uid != 0 || (metadata.mode & 0o022) != 0 {
            return Err(OwnerError::Invalid);
        }
        Ok(Self {
            unique_name,
            pid: peer.pid,
            uid: peer.uid,
            executable,
        })
    }

    /// Re-checks the same peer is still alive behind the same unique name.
    pub fn still_bound(
        &self,
        facts: &dyn ProcessFacts,
        peer: &super::port::PeerCredentials,
    ) -> bool {
        peer.pid == self.pid && peer.uid == self.uid && facts.executable_path(peer.pid).is_ok()
    }
}

/// Production `/proc`-backed facts (Linux only).
#[cfg(target_os = "linux")]
pub struct ProcProcessFacts;

#[cfg(target_os = "linux")]
impl ProcessFacts for ProcProcessFacts {
    fn effective_uid(&self) -> u32 {
        // Security note: /proc/self ownership mirrors our own effective uid.
        // This is a filesystem ownership probe of our own process entry, not a
        // secret or environment read; it avoids unsafe libc geteuid.
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .map(|metadata| metadata.uid())
            .unwrap_or(u32::MAX)
    }

    fn executable_path(&self, pid: u32) -> Result<PathBuf, OwnerError> {
        let link = format!("/proc/{pid}/exe");
        let resolved = std::fs::read_link(&link).map_err(|_| OwnerError::Unreadable)?;
        if !resolved.is_absolute() {
            return Err(OwnerError::Unreadable);
        }
        // "(deleted)" suffix means the binary was replaced after start.
        if resolved.to_string_lossy().ends_with(" (deleted)") {
            return Err(OwnerError::Unreadable);
        }
        Ok(resolved)
    }

    fn executable_metadata(&self, path: &Path) -> Result<ExecutableFacts, OwnerError> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).map_err(|_| OwnerError::Unreadable)?;
        Ok(ExecutableFacts {
            uid: metadata.uid(),
            mode: metadata.mode(),
        })
    }
}
