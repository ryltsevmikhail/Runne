//! Fail-closed Linux structured-command gate. Caller owns approval and durable intent.
//! Filesystem and mount controls are enforced here; network policy remains profile-owned.
#![allow(unsafe_code)]

mod child;
mod gate;
mod io;
mod policy;
mod snapshot;
mod spec;

pub use io::{LinuxCommandOutputChunkV1, LinuxCommandOutputLimitsV1};
pub use snapshot::SealedExecutableSnapshot;
pub use spec::{GatedLinuxChild, LinuxCommandError, LinuxCommandExecutable, LinuxCommandSpec};
