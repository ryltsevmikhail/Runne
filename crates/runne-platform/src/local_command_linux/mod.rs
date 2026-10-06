//! Fail-closed Linux structured-command gate. Caller owns approval and durable intent.
//! Filesystem and mount controls are enforced here; network policy remains profile-owned.
#![allow(unsafe_code)]

mod child;
mod composite_admission;
mod error;
mod gate;
mod io;
mod policy;
mod snapshot;
mod spec;

pub use composite_admission::LinuxCompositeScopeAdmission;
pub use error::LinuxCommandError;
pub use io::{LinuxCommandOutputChunkV1, LinuxCommandOutputLimitsV1};
pub use snapshot::SealedExecutableSnapshot;
pub use spec::{
    GatedLinuxChild, LinuxCommandContainmentV1, LinuxCommandExecutable, LinuxCommandSpec,
};
