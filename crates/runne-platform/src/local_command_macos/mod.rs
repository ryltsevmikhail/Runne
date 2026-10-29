//! Fail-closed macOS structured-command primitives.
//!
//! macOS lacks the Linux cgroup and `openat2` model. This adapter keeps the
//! same closed facts where they are portable and fails closed where a native
//! proof is unavailable.
#![allow(unsafe_code)]

mod area;
mod error;
mod exit;
mod process;
mod sealed;

pub use area::{MacOsAreaIdentity, MacOsManagedArea, VerifiedEmptyMacOsArea};
pub use error::MacOsCommandError;
pub use error::MacOsCommandError as LinuxCommandError;
pub use exit::{LinuxLeaderExitKindV1, LinuxLeaderExitObservationV1};
pub use process::{MacOsCommandSpec, MacOsManagedChild};
pub use sealed::SealedExecutableSnapshot;
