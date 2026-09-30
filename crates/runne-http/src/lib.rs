//! Runne HTTP Host
//!
//! Axum-based HTTP/1.1 API host implementing:
//! health, admission, commands, queries, replay, SSE, and auth middleware.

pub mod admission;
pub mod approvals;
pub mod auth;
pub mod command_reconciliation;
pub mod commands;
pub mod conversation_writer_lease;
pub mod conversations;
pub mod editors;
pub mod error;
pub mod health;
pub mod limits;
pub mod local_engine;
pub mod local_session;
pub mod middleware;
pub mod opencode;
pub mod operational_telemetry;
pub mod processes;
/// Protected, runtime-owned Project Trust metadata and explicit decision path.
pub mod project_trust_control;
pub mod project_workspace;
pub(crate) mod provider_credential_enrollment;
pub use provider_credential_enrollment::{
    ProviderCredentialEnrollmentHttpAdmission, ProviderCredentialEnrollmentHttpAdmissionResolver,
    ProviderCredentialEnrollmentHttpState, provider_credential_enrollment_router,
};
pub mod provider_credentials;
pub mod queries;
pub mod replay;
pub mod router;
pub mod runtime_profile;
mod runtime_profile_helpers;
pub mod secure_local_host;
pub mod sse;
pub mod task_runs;
pub mod workspace_diffs;
pub mod workspace_files;
