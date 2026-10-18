//! Authenticated V2 permission-mode status and command transport.

use std::sync::Arc;

use axum::{Router, middleware, routing::get};
use runne_api::PermissionModeControlHostV2;

mod error;
mod handlers;
mod native_pending;

struct PermissionModeControlHttpState<H>(Arc<H>);

impl<H> Clone for PermissionModeControlHttpState<H> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<H> PermissionModeControlHttpState<H> {
    fn new(host: H) -> Self {
        Self(Arc::new(host))
    }
}

/// Builds the V2 permission-mode status and command routes.
///
/// The containing runtime router must apply `SessionAuthLayer` and request-ID
/// middleware; this route never supplies a default principal.
pub fn permission_mode_control_router<H: PermissionModeControlHostV2 + 'static>(host: H) -> Router {
    Router::new()
        .route(
            "/v2/workspaces/{workspace_id}/permission-mode",
            get(handlers::status::<H>).post(handlers::request_mode_change::<H>),
        )
        .route(
            "/v2/workspaces/{workspace_id}/permission-mode/commands/{command_id}",
            get(handlers::command_status::<H>),
        )
        .with_state(PermissionModeControlHttpState::new(host))
        .layer(middleware::from_fn(error::no_store_middleware))
}

/// Builds authenticated, read-only discovery for native mode confirmation.
pub fn permission_mode_native_pending_router<
    H: runne_api::PermissionModeNativePendingHostV2 + 'static,
>(
    host: H,
) -> Router {
    native_pending::router(host)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_support {
    use super::permission_mode_control_router;
    use crate::{auth::SessionAuthLayer, middleware::request_id_middleware};
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderValue, Request},
        middleware,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    pub(super) use runne_api::ApiPrincipalId;
    use runne_api::{
        DaemonInstanceId, PermissionEffectiveStateV1, PermissionModeChangeRequestV1,
        PermissionModeCommandStatusV2, PermissionModeControlHostV2, PermissionModeHostErrorV1,
        PermissionModeNotReadyReasonV1, PermissionModeStatusV1, PermissionModeV1,
        PermissionNetworkStateV1, PermissionPresetVersionV1, RuntimeSessionBinding,
        StableRuntimeBinding, ValidatedPermissionModeChangeV1,
    };
    use runne_application::local_session::{
        BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
    };
    pub(super) use runne_domain::id::{CommandId, WorkspaceId};
    use runne_domain::{event::Sensitivity, id::EventLogLineageId};
    pub(super) use std::sync::{Arc, Mutex};
    use std::time::Duration;
    pub(super) use tower::ServiceExt;

    pub(super) const WORKSPACE_BYTES: [u8; 16] =
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
    pub(super) const COMMAND_BYTES: [u8; 16] =
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
    pub(super) const OTHER_WORKSPACE_BYTES: [u8; 16] =
        [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];
    const PRINCIPAL: &str = "local-owner";

    #[derive(Debug, Eq, PartialEq)]
    pub(super) enum HostCall {
        Status(ApiPrincipalId, WorkspaceId),
        Request(ApiPrincipalId, CommandId, String),
        CommandStatus(ApiPrincipalId, WorkspaceId, CommandId),
    }

    pub(super) struct TestHost(pub(super) Arc<Mutex<Vec<HostCall>>>);

    impl PermissionModeControlHostV2 for TestHost {
        fn status(
            &self,
            principal: ApiPrincipalId,
            workspace_id: WorkspaceId,
        ) -> impl std::future::Future<
            Output = Result<PermissionModeStatusV1, PermissionModeHostErrorV1>,
        > + Send {
            self.0
                .lock()
                .unwrap()
                .push(HostCall::Status(principal, workspace_id));
            std::future::ready(Ok(status()))
        }

        fn request_mode_change(
            &self,
            principal: ApiPrincipalId,
            request: ValidatedPermissionModeChangeV1,
        ) -> impl std::future::Future<
            Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>,
        > + Send {
            self.0.lock().unwrap().push(HostCall::Request(
                principal,
                request.command_id(),
                request.idempotency_key().as_str().to_owned(),
            ));
            std::future::ready(Ok(
                PermissionModeCommandStatusV2::PendingNativeConfirmation {
                    command_id: request.command_id(),
                    expires_at_unix_ms: request.expires_at_unix_ms().unwrap_or(2_000),
                },
            ))
        }

        fn command_status(
            &self,
            principal: ApiPrincipalId,
            workspace_id: WorkspaceId,
            command_id: CommandId,
        ) -> impl std::future::Future<
            Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>,
        > + Send {
            self.0.lock().unwrap().push(HostCall::CommandStatus(
                principal,
                workspace_id,
                command_id,
            ));
            std::future::ready(Ok(PermissionModeCommandStatusV2::PendingReauthentication {
                command_id,
                expires_at_unix_ms: 2_000,
            }))
        }
    }

    fn status() -> PermissionModeStatusV1 {
        PermissionModeStatusV1 {
            selected_mode: PermissionModeV1::RiskBased,
            effective: PermissionEffectiveStateV1::NotReady {
                reason: PermissionModeNotReadyReasonV1::PresetUnavailable,
            },
            authorization_revision: 4,
            preset_version: PermissionPresetVersionV1::V1,
            managed_policy_version: 2,
            pending_approval_ids: Vec::new(),
            containment: None,
            network_state: PermissionNetworkStateV1::Unavailable,
            expires_at_unix_ms: None,
        }
    }

    pub(super) fn request_body(workspace: WorkspaceId, command: CommandId) -> String {
        serde_json::to_string(&PermissionModeChangeRequestV1::new(
            workspace,
            command,
            "mode-change-key",
            4,
            PermissionModeV1::RiskBased,
            1,
            Some(1_700_000_000_000),
        ))
        .unwrap()
    }

    fn auth() -> (SessionAuthLayer, HeaderValue) {
        let binding = RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 4],
                ApiPrincipalId::new(PRINCIPAL).unwrap(),
                "018f2e3a-7000-7000-8000-000000000005"
                    .parse::<EventLogLineageId>()
                    .unwrap(),
                "gocode-ui-client/2",
                [3; 32],
                [4; 32],
            )
            .unwrap(),
            DaemonInstanceId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 6]),
            1,
            [5; 16],
            1,
            Sensitivity::Internal,
            [6; 32],
        )
        .unwrap();
        let mut service = LocalSessionService::new(binding.clone(), [7; 32]);
        let challenge = service
            .issue_challenge([8; 32], [9; 32], Duration::ZERO)
            .unwrap();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&[7; 32]).unwrap();
        mac.update(&bootstrap_proof_transcript(&binding, [9; 32], [8; 32]));
        service
            .authenticate(
                challenge.id,
                BootstrapProof::new(mac.finalize().into_bytes().into()),
                [10; 32],
                Duration::ZERO,
            )
            .unwrap();
        let header = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode([10; 32]))
            .parse()
            .unwrap();
        (
            SessionAuthLayer::new(
                Arc::new(Mutex::new(service)),
                binding,
                Arc::new(|| Duration::ZERO),
            ),
            header,
        )
    }

    pub(super) fn app(calls: Arc<Mutex<Vec<HostCall>>>) -> (axum::Router, HeaderValue) {
        let (auth_layer, authorization) = auth();
        (
            permission_mode_control_router(TestHost(calls))
                .layer(auth_layer)
                .layer(middleware::from_fn(request_id_middleware)),
            authorization,
        )
    }

    pub(super) fn request(
        method: &str,
        uri: &str,
        auth: Option<&HeaderValue>,
        body: &str,
        headers: &[(&str, String)],
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(auth) = auth {
            builder = builder.header("authorization", auth.clone());
        }
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }

    pub(super) async fn assert_no_store(response: &axum::response::Response) {
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().contains_key("x-request-id"));
    }

    pub(super) async fn body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
    }
}
