//! Authenticated exact runtime profile query.

use axum::{
    Json, Router,
    extract::Extension,
    response::{IntoResponse, Response},
    routing::get,
};
use gocode_application::local_session::AuthenticatedRuntimeSession;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Immutable exact profile advertised by the running daemon.
#[derive(Clone)]
pub struct RuntimeProfileHttpState {
    profile_id: &'static str,
    schema_hash: &'static str,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
}

impl RuntimeProfileHttpState {
    /// Creates the built-in profile response.
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use gocode_api::{
        ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding,
    };
    use gocode_application::local_session::AuthenticatedRuntimeSession;
    use gocode_domain::{event::Sensitivity, id::EventLogLineageId};
    use std::time::Duration;
    use tower::ServiceExt;

    fn binding() -> RuntimeSessionBinding {
        RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
                ApiPrincipalId::new("local-owner").unwrap(),
                "018f2e3a-7000-7000-8000-000000000003"
                    .parse::<EventLogLineageId>()
                    .unwrap(),
                "gocode-ui-client/1",
                [3; 32],
                ordered_capability_digest(&["conversation.create.v1", "conversation.list.v1"]),
            )
            .unwrap(),
            DaemonInstanceId::from_bytes([
                1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2,
            ]),
            7,
            [5; 16],
            3,
            Sensitivity::Internal,
            [6; 32],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn session_profile_is_exact_binding_tuple_without_secret_fields() {
        let state = RuntimeProfileHttpState::new(
            "untrusted-handler-copy",
            "untrusted-handler-copy",
            "0.1.0-test",
            &["conversation.create.v1", "conversation.list.v1"],
        );
        let session = AuthenticatedRuntimeSession {
            binding: binding(),
            expires_at_monotonic: Duration::from_secs(600),
        };
        let mut request = Request::builder()
            .uri("/v1/runtime/profile")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(session);
        let response = runtime_profile_session_router(state)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(body["profileId"], "gocode-ui-client/1");
        assert_eq!(body["schemaHash"], hex::encode([3; 32]));
        assert_eq!(body["runtimeVersion"], "0.1.0-test");
        assert_eq!(
            body["capabilities"],
            serde_json::json!(["conversation.create.v1", "conversation.list.v1"])
        );
        assert_eq!(
            body["capabilityDigest"],
            hex::encode(ordered_capability_digest(&[
                "conversation.create.v1",
                "conversation.list.v1"
            ]))
        );
        assert_eq!(
            body["authorityId"],
            hex::encode([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(body["principalId"], "local-owner");
        assert_eq!(
            body["eventLogLineageId"],
            "018f2e3a-7000-7000-8000-000000000003"
        );
        assert_eq!(
            body["daemonInstanceId"],
            "018f2e3a-7000-7000-8000-000000000002"
        );
        assert_eq!(body["launchGeneration"], 7);
        assert_eq!(body["sessionId"], hex::encode([5; 16]));
        assert_eq!(body["authorizationEpoch"], 3);
        assert_eq!(body["sensitivityCeiling"], "Internal");
        assert_eq!(body["certificateSha256"], hex::encode([6; 32]));
        for forbidden in [
            "authority",
            "bootstrap",
            "proof",
            "privateKey",
            "replayIntegrityKey",
            "expiresAtMonotonic",
            "token",
            "bearer",
        ] {
            assert!(body.get(forbidden).is_none(), "profile leaked {forbidden}");
        }
    }

    #[test]
    fn ordered_capability_digest_is_domain_separated_and_ordered() {
        assert_eq!(
            hex::encode(ordered_capability_digest(&["a", "b"])),
            "91cdbd7c7dd645123152088fe50eca060dbc7cba7800af8440bab92568f8f89a"
        );
        assert_ne!(
            ordered_capability_digest(&["a", "b"]),
            ordered_capability_digest(&["b", "a"])
        );
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeProfileWire {
    profile_id: &'static str,
    schema_hash: &'static str,
    runtime_version: &'static str,
    capabilities: &'static [&'static str],
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
    Router::new()
        .route("/v1/runtime/profile", get(session_runtime_profile))
        .with_state(state)
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
        sensitivity_ceiling: format!("{:?}", ephemeral.sensitivity_ceiling()),
        certificate_sha256: hex::encode(session.binding.certificate_sha256()),
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
}
