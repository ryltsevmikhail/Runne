//! Production Axum router composition.
//!
//! Only implemented canonical routes are mounted. Legacy command, query and
//! replay stubs remain outside this production surface.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, middleware as axum_mw};
use runne_api::{
    ApprovalCommandHostPort, ApprovalQueryHostPort, ConversationCommandHostPort,
    ConversationQueryHostPort, OPERATIONAL_TELEMETRY_CAPABILITY_V1,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceQueryHostPort, TaskRunCommandHostPort,
    TaskRunQueryHostPort, WorkspaceDiffHostPort, WorkspaceFileHostPort,
};

use crate::admission::{AdmissionState, admission_middleware};
use crate::approvals::{ApprovalHttpState, approval_router};
use crate::auth::{AuthLayer, SessionAuthLayer};
use crate::command_reconciliation::{
    CommandReconciliationHttpState, command_reconciliation_router,
};
use crate::conversations::{ConversationHttpState, conversation_router};
use crate::health::{HealthState, health_router};
use crate::local_session::{LocalSessionHttpState, VerifiedLocalTls, local_session_router};
use crate::middleware::request_id_middleware;
use crate::opencode::{OpenCodeSessionState, opencode_session_router};
use crate::operational_telemetry::{
    OperationalTelemetryHttpState, no_store_response, operational_telemetry_router,
};
use crate::processes::{ProcessHttpState, process_router};
use crate::project_workspace::{ProjectWorkspaceHttpState, project_workspace_router};
use crate::replay::{ReplayHttpState, replay_router};
use crate::runtime_profile::{
    RuntimeProfileHttpState, runtime_profile_router, runtime_profile_session_router,
};
use crate::task_runs::{TaskRunHttpState, canonical_task_run_router, task_run_router};
use crate::workspace_diffs::{WorkspaceDiffHttpState, workspace_diff_router};
use crate::workspace_files::{WorkspaceFileHttpState, workspace_file_router};

include!("router_parts/production.rs");
include!("router_parts/legacy_routers.rs");
include!("router_parts/local_engine.rs");
include!("router_parts/provider_credential_admission.rs");
include!("router_parts/project_workspace.rs");
include!("router_parts/command_reconciliation.rs");
include!("router_parts/command_reconciliation_production.rs");
include!("router_parts/approvals.rs");

#[cfg(test)]
mod tests {
    include!("router_parts/tests_support.rs");
    include!("router_parts/bootstrap_test_support.rs");
    include!("router_parts/replay_epoch_support.rs");
    include!("router_parts/tests.rs");
    include!("router_parts/tests_admission.rs");
}
