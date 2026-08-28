//! Authenticated exact runtime profile query.
#![allow(dead_code)] // Mounted only by the crate-owned local TLS boundary in Task 4B.

use crate::provider_credentials::provider_credential_router;
use crate::runtime_profile_helpers::sensitivity_label;
use axum::{
    Json, Router,
    extract::Extension,
    response::{IntoResponse, Response},
    routing::get,
};
use runne_api::ProviderStatusSnapshotV1;
use runne_application::local_session::AuthenticatedRuntimeSession;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
enum ProviderStatuses {
    Static(Vec<ProviderStatusSnapshotV1>),
    Dynamic(Arc<dyn Fn() -> Vec<ProviderStatusSnapshotV1> + Send + Sync>),
}

impl ProviderStatuses {
    fn current(&self) -> Vec<ProviderStatusSnapshotV1> {
        match self {
            Self::Static(statuses) => statuses.clone(),
            Self::Dynamic(provider) => provider(),
        }
    }
}

/// Immutable exact profile advertised by the running daemon.
#[derive(Clone)]
pub struct RuntimeProfileHttpState {
    profile_id: &'static str,
    schema_hash: &'static str,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
    provider_statuses: ProviderStatuses,
}

impl RuntimeProfileHttpState {
    #[must_use]
    pub const fn new(
        profile_id: &'static str,
        schema_hash: &'static str,
        runtime_version: &'static str,
        capabilities: &'static [&'static str],
    ) -> Self {
        Self {
            profile_id,
            schema_hash,
            runtime_version,
            capabilities,
            provider_statuses: ProviderStatuses::Static(Vec::new()),
        }
    }

    #[must_use]
    pub fn with_provider_statuses(mut self, statuses: Vec<ProviderStatusSnapshotV1>) -> Self {
        self.provider_statuses = ProviderStatuses::Static(statuses);
        self
    }

    /// Reads provider status on each profile request without changing profile identity.
    #[must_use]
    pub fn with_dynamic_provider_statuses(
        mut self,
        statuses: Arc<dyn Fn() -> Vec<ProviderStatusSnapshotV1> + Send + Sync>,
    ) -> Self {
        self.provider_statuses = ProviderStatuses::Dynamic(statuses);
        self
    }
}

#[cfg(test)]
mod tests;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeProfileWire {
    profile_id: &'static str,
    schema_hash: &'static str,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
    provider_statuses: Vec<ProviderStatusSnapshotV1>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionRuntimeProfileWire {
    profile_id: String,
    schema_hash: String,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
    capability_digest: String,
    authority_id: String,
    principal_id: String,
    event_log_lineage_id: String,
    daemon_instance_id: String,
    launch_generation: u64,
    session_id: String,
    authorization_epoch: u64,
    sensitivity_ceiling: String,
    certificate_sha256: String,
    provider_statuses: Vec<ProviderStatusSnapshotV1>,
}

/// Builds the profile query route. Authentication is applied by the parent
/// protected router.
pub fn runtime_profile_router(state: RuntimeProfileHttpState) -> Router {
    Router::new().route(
        "/v1/runtime/profile",
        get(move || async move {
            Json(RuntimeProfileWire {
                profile_id: state.profile_id,
                schema_hash: state.schema_hash,
                runtime_version: state.runtime_version,
                capabilities: state.capabilities,
                provider_statuses: state.provider_statuses.current(),
            })
        }),
    )
}

/// Builds the local-session-authenticated profile query route.
///
/// The identity fields intentionally come from the authenticated request
/// extension rather than from daemon-owned handler state. This keeps the
/// advertised profile tied to the authority validated by `SessionAuthLayer`.
pub(crate) fn runtime_profile_session_router(state: RuntimeProfileHttpState) -> Router {
    let router = Router::new()
        .route("/v1/runtime/profile", get(session_runtime_profile))
        .with_state(state.clone());
    router.merge(provider_credential_router())
}

async fn session_runtime_profile(
    Extension(session): Extension<AuthenticatedRuntimeSession>,
    axum::extract::State(state): axum::extract::State<RuntimeProfileHttpState>,
) -> Response {
    let stable = session.binding.stable();
    let ephemeral = session.binding.ephemeral();
    Json(SessionRuntimeProfileWire {
        profile_id: stable.profile_id().to_owned(),
        schema_hash: hex::encode(stable.schema_hash()),
        runtime_version: state.runtime_version,
        capabilities: state.capabilities,
        capability_digest: hex::encode(stable.capability_digest()),
        authority_id: hex::encode(stable.authority_id()),
        principal_id: stable.principal_id().as_str().to_owned(),
        event_log_lineage_id: stable.lineage_id().to_string(),
        daemon_instance_id: ephemeral.daemon_instance_id().to_string(),
        launch_generation: ephemeral.launch_generation(),
        session_id: hex::encode(ephemeral.session_id()),
        authorization_epoch: ephemeral.authorization_epoch(),
        sensitivity_ceiling: sensitivity_label(ephemeral.sensitivity_ceiling()).to_owned(),
        certificate_sha256: hex::encode(session.binding.certificate_sha256()),
        provider_statuses: state.provider_statuses.current(),
    })
    .into_response()
}

/// Computes the domain-separated digest of the exact ordered capabilities.
#[must_use]
pub fn ordered_capability_digest(capabilities: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-runtime/capability-digest/v1\0");
    hasher.update(
        u32::try_from(capabilities.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for capability in capabilities {
        let bytes = capability.as_bytes();
        hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

impl RuntimeProfileHttpState {
    pub(crate) fn ordered_capability_digest(&self) -> [u8; 32] {
        ordered_capability_digest(self.capabilities)
    }

    pub(crate) fn advertises(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability)
    }
}
