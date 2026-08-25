#![forbid(unsafe_code)]

//! API-level contracts for the Runne runtime host boundary.

/// Closed authoritative-command reconciliation contracts.
pub mod command_reconciliation;

/// Runtime-owned approval query and decision contracts.
pub mod approval;

/// Canonical Conversation and message contracts.
pub mod conversation;
/// Runtime-owned scoped external-editor action contracts.
pub mod editor;
/// Runtime host port contracts.
pub mod host_port;
/// Local runtime-session binding contracts.
pub mod local_session;
/// Closed runtime operational telemetry wire contracts.
pub mod operational_telemetry;
/// API command principals and actors.
pub mod principal;
/// Runtime-owned process and bounded terminal-output contracts.
pub mod process;
/// Canonical Project and Workspace command and query contracts.
pub mod project_workspace;
/// Protected bundled-runtime activation contracts.
pub mod protected_activation;
/// Runtime-owned provider credential control contracts.
pub mod provider_credential;
/// Runtime-owned provider readiness projections.
pub mod provider_status;
/// Public replay binding contracts.
pub mod replay;
/// Validated OpenCode `Session.Info` wire values.
pub mod session_info;
/// Canonical TaskRun command and query contracts.
pub mod task_run;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;
/// API data transfer objects.
pub mod types;
pub mod workspace_diff;
pub mod workspace_diff_query;
/// Canonical bounded Workspace file query contracts.
pub mod workspace_files;

/// Stable workspace identifier transported across the public host boundary.
pub use runne_domain::id::{EventLogLineageId, WorkspaceId};

pub use approval::*;
pub use command_reconciliation::*;
pub use conversation::*;
pub use editor::*;
pub use host_port::*;
pub use local_session::*;
pub use operational_telemetry::*;
pub use principal::*;
pub use process::*;
pub use project_workspace::*;
pub use protected_activation::*;
pub use provider_credential::*;
pub use provider_status::*;
pub use replay::*;
pub use session_info::*;
pub use task_run::*;
pub use types::*;
pub use workspace_diff::*;
pub use workspace_diff_query::*;
pub use workspace_files::*;
