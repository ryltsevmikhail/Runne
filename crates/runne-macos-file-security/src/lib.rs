//! Descriptor-only macOS ACL and main-executable admission.
//!
//! These predicates neither authorize file writes nor retain filesystem identities.
//! Callers must recheck their required ownership and lifecycle facts before effects.

#![cfg(target_os = "macos")]

use std::os::fd::{AsRawFd, BorrowedFd};

/// An ACL exists, or the operating system could not establish its absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSecurityRejected;

unsafe extern "C" {
    fn runne_macos_fd_has_no_extended_acl(fd: std::ffi::c_int) -> std::ffi::c_int;
    fn runne_macos_fd_is_current_executable_file(fd: std::ffi::c_int) -> std::ffi::c_int;
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

/// Requires a regular, single-linked descriptor for this process's main image.
///
/// The native observation obtains the address only from dyld image zero, then
/// asks the kernel for that exact mapping's vnode. It does not resolve a caller
/// path or accept an arbitrary executable mapping.
///
/// # Errors
///
/// Returns `FileSecurityRejected` unless the descriptor and mapped main image
/// have the same vnode identity and both retain exactly one link.
pub fn require_current_executable_file(fd: BorrowedFd<'_>) -> Result<(), FileSecurityRejected> {
    // SAFETY: the borrow keeps the descriptor alive. The native function only
    // queries its descriptor and current process mapping; it retains neither.
    let result = unsafe { runne_macos_fd_is_current_executable_file(fd.as_raw_fd()) };
    (result == 1).then_some(()).ok_or(FileSecurityRejected)
}

#[cfg(test)]
mod tests;
