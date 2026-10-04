//! Fail-closed Linux structured-command gate. Caller owns approval and durable intent.
//! Filesystem and mount controls are enforced here; network policy remains profile-owned.
#![allow(unsafe_code)]

mod child;
mod gate;
mod policy;
mod snapshot;
mod spec;

pub use snapshot::SealedExecutableSnapshot;
pub use spec::{GatedLinuxChild, LinuxCommandError, LinuxCommandExecutable, LinuxCommandSpec};
