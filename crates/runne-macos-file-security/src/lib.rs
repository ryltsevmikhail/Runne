//! Descriptor-only macOS extended ACL admission.
//!
//! This predicate neither verifies ownership nor retains filesystem identities.
//! Callers must validate those facts and recheck before security-sensitive effects.

#![cfg(target_os = "macos")]

use std::os::fd::{AsRawFd, BorrowedFd};

/// An ACL exists, or the operating system could not establish its absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSecurityRejected;

unsafe extern "C" {
    fn runne_macos_fd_has_no_extended_acl(fd: std::ffi::c_int) -> std::ffi::c_int;
}

/// Requires an explicit successful OS observation that the descriptor has no ACL.
///
/// Any extended ACL, including an empty or deny-only ACL, is rejected. This does
/// not inspect path aliases, authorize file writes, or interpret principal names.
///
/// # Errors
///
/// Returns `FileSecurityRejected` for an ACL or any failed native query.
pub fn require_no_extended_acl(fd: BorrowedFd<'_>) -> Result<(), FileSecurityRejected> {
    // SAFETY: the borrow keeps the descriptor alive. The native function retains
    // no Rust memory or descriptor and releases its own filesec allocation.
    let result = unsafe { runne_macos_fd_has_no_extended_acl(fd.as_raw_fd()) };
    (result == 1).then_some(()).ok_or(FileSecurityRejected)
}

#[cfg(test)]
mod tests;
