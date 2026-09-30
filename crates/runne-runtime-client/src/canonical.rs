//! Authenticated canonical command/query transport.

// Re-exported so clients can name the create-conversation scope type without
// a direct runne-api dependency (runne-api is optional for some clients).
pub use runne_api::ConversationContextScope;

include!("canonical/types.rs");
include!("canonical/task_run.rs");
include!("canonical/task_run_list.rs");
include!("canonical/session_authority_baseline.rs");
include!("canonical/session_binding.rs");
include!("canonical/transport_kind.rs");
include!("canonical/client.rs");
include!("canonical/task_runs_client.rs");
include!("canonical/task_run_submit.rs");
include!("canonical/capabilities.rs");
include!("canonical/capabilities_v2.rs");
#[cfg(test)]
include!("canonical/capabilities_tests.rs");
include!("canonical/requests.rs");
include!("canonical/conversation_writer_lease.rs");
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
include!("canonical/provider_credential_enrollment.rs");
include!("canonical/enrollment_wire.rs");

mod project_workspace;
pub use project_workspace::*;

#[cfg(test)]
include!("canonical/operational_telemetry_tests.rs");
#[cfg(test)]
include!("canonical/approval_tests.rs");
