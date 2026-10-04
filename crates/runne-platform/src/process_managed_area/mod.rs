//! Linux cgroup-v2 managed process areas.
//!
//! This is a lifecycle primitive. It does not launch commands or prevent an
//! untrusted same-UID process from migrating itself between cgroups.

mod area;
mod current;
mod identity;
mod root;

pub use area::{LinuxManagedArea, ManagedAreaError, VerifiedEmptyManagedArea};
pub use identity::{ManagedAreaBinding, ManagedAreaIdentity};
pub use root::LinuxManagedAreaRoot;
