#![forbid(unsafe_code)]

//! API-level contracts for the GOCODE runtime host boundary.

/// Canonical Conversation and message contracts.
pub mod conversation;
/// Runtime host port contracts.
pub mod host_port;
/// Local runtime-session binding contracts.
pub mod local_session;
/// API command principals and actors.
pub mod principal;
/// Protected bundled-runtime activation contracts.
pub mod protected_activation;
/// Public replay binding contracts.
pub mod replay;
/// Validated OpenCode `Session.Info` wire values.
pub mod session_info;
/// Canonical TaskRun command and query contracts.
pub mod task_run;
/// API data transfer objects.
pub mod types;

pub use conversation::*;
pub use host_port::*;
pub use local_session::*;
pub use principal::*;
pub use protected_activation::*;
pub use replay::*;
pub use session_info::*;
pub use task_run::*;
pub use types::*;
