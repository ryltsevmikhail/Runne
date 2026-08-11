#![forbid(unsafe_code)]

//! API-level contracts for the GOCODE runtime host boundary.

/// Canonical Conversation and message contracts.
pub mod conversation;
/// Runtime host port contracts.
pub mod host_port;
/// Local runtime-session binding contracts.
pub mod local_session;
/// Closed runtime operational telemetry wire contracts.
pub mod operational_telemetry;
/// API command principals and actors.
pub mod principal;
/// Canonical Project and Workspace command and query contracts.
pub mod project_workspace;
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

/// Stable workspace identifier transported across the public host boundary.
pub use gocode_domain::id::WorkspaceId;

pub use conversation::*;
pub use host_port::*;
pub use local_session::*;
pub use operational_telemetry::*;
pub use principal::*;
pub use project_workspace::*;
pub use protected_activation::*;
pub use replay::*;
pub use session_info::*;
pub use task_run::*;
pub use types::*;
