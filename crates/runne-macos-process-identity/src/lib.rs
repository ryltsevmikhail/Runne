//! Opaque kernel-observed macOS process-start identities.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod ffi;

use std::fmt;
use std::num::NonZeroU32;

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

impl fmt::Debug for MacOsProcessStartIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MacOsProcessStartIdentity(<kernel-observed>)")
    }
}

/// Opaque macOS kernel process-observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacOsProcessIdentityError;
