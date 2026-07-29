#![forbid(unsafe_code)]

//! API-level contracts for the GOCODE runtime host boundary.

/// Runtime host port contracts.
pub mod host_port;
/// API command principals and actors.
pub mod principal;
/// Validated OpenCode `Session.Info` wire values.
pub mod session_info;
/// Canonical TaskRun command and query contracts.
pub mod task_run;
/// API data transfer objects.
pub mod types;

pub use host_port::*;
pub use principal::*;
pub use session_info::*;
pub use task_run::*;
pub use types::*;
