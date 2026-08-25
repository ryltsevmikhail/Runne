//! Authenticated canonical command/query transport.

include!("canonical/types.rs");
include!("canonical/task_run.rs");
include!("canonical/task_run_list.rs");
include!("canonical/session_authority_baseline.rs");
include!("canonical/session_binding.rs");
include!("canonical/transport_kind.rs");
include!("canonical/client.rs");
include!("canonical/capabilities.rs");
include!("canonical/requests.rs");
include!("canonical/errors.rs");
include!("canonical/wire.rs");
include!("canonical/operational_telemetry.rs");
include!("canonical/reconciliation.rs");
include!("canonical/workspace_files.rs");
include!("canonical/workspace_diffs.rs");
include!("canonical/processes.rs");
include!("canonical/editor.rs");
include!("canonical/approvals.rs");
include!("canonical/provider_credentials.rs");

mod project_workspace;
pub use project_workspace::*;

#[cfg(test)]
include!("canonical/operational_telemetry_tests.rs");
#[cfg(test)]
include!("canonical/approval_tests.rs");
