//! Opaque kernel-observed macOS process-start identities.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod ffi;

use std::fmt;
use std::fs::Metadata;
use std::num::NonZeroU32;
use std::path::Path;

/// Opaque digest of a kernel-observed macOS process start tuple.
#[derive(Eq, PartialEq)]
pub struct MacOsProcessStartIdentity([u8; 32]);

impl MacOsProcessStartIdentity {
    /// Observes one live process through the macOS kernel process API.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure when the kernel cannot provide a complete,
    /// matching process-start tuple.
    pub fn observe(pid: NonZeroU32) -> Result<Self, MacOsProcessIdentityError> {
        ffi::observe(pid).map(Self)
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.0
    }
}

/// Opaque vnode identity for the executable mapping of one live process.
#[derive(Eq, PartialEq)]
pub struct MacOsProcessExecutableIdentity(ffi::ExecutableVnodeIdentity);

impl MacOsProcessExecutableIdentity {
    /// Observes the executable VM mapping whose kernel path matches `path`.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure when no exact executable vnode is observable.
    pub fn observe(pid: NonZeroU32, path: &Path) -> Result<Self, MacOsProcessIdentityError> {
        ffi::observe_executable_vnode(pid, path).map(Self)
    }

    /// Matches the observed vnode to metadata from an already-open file.
    #[must_use]
    pub fn matches_file(&self, metadata: &Metadata) -> bool {
        self.0.matches_file(metadata)
    }
}

impl fmt::Debug for MacOsProcessExecutableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsProcessExecutableIdentity(<kernel-observed>)")
    }
}

impl fmt::Debug for MacOsProcessStartIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsProcessStartIdentity(<kernel-observed>)")
    }
}

/// Opaque macOS kernel process-observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsProcessIdentityError;
