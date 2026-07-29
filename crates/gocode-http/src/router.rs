//! Production Axum router composition.
//!
//! Only implemented canonical routes are mounted. Legacy command, query and
//! replay stubs remain outside this production surface.

use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Request, Response},
    middleware as axum_mw,
};
use gocode_api::{
    ConversationCommandHostPort, ConversationQueryHostPort, TaskRunCommandHostPort,
    TaskRunQueryHostPort,
};

use crate::admission::{AdmissionState, admission_middleware};
use crate::auth::{AuthLayer, SessionAuthLayer};
use crate::conversations::{ConversationHttpState, conversation_router};
use crate::health::{HealthState, health_router};
use crate::local_session::{LocalSessionHttpState, VerifiedLocalTls, local_session_router};
use crate::middleware::request_id_middleware;
use crate::opencode::{OpenCodeSessionState, opencode_session_router};
use crate::replay::{ReplayHttpState, replay_router};
use crate::runtime_profile::{
    RuntimeProfileHttpState, runtime_profile_router, runtime_profile_session_router,
};
use crate::task_runs::{TaskRunHttpState, task_run_router};

/// Builds the TLS-gated local-session bootstrap surface without changing the
/// legacy bearer-protected production router before the Task 4 cutover.
pub(crate) fn create_local_session_bootstrap_router(state: LocalSessionHttpState) -> Router {
    local_session_router(state)
}

/// Opaque TLS-only local runtime HTTP composition.
///
/// The host is the sole public composition point for the local-session
/// bootstrap routes and the canonical session-authenticated routes. It never
/// returns an Axum `Router`; the crate-owned TLS serving boundary is the only
/// code allowed to consume its opaque service.
pub struct SecureLocalHttpHost {
    router: Router,
}

/// Rejected inconsistent local runtime profile configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecureLocalHttpHostError {
    /// The advertised ordered capabilities do not match the authenticated binding.
    #[error("runtime profile capability digest does not match session binding")]
    CapabilityDigestMismatch,
}

impl SecureLocalHttpHost {
    /// Composes bootstrap, health, and every canonical protected route over one
    /// shared local-session service.
    #[allow(clippy::too_many_arguments)]
    pub fn new<T, C>(
        health_state: HealthState,
        admission_state: AdmissionState,
        local_session_service: Arc<Mutex<gocode_application::local_session::LocalSessionService>>,
        binding: gocode_api::RuntimeSessionBinding,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        runtime_profile_state: RuntimeProfileHttpState,
        task_run_state: TaskRunHttpState<T>,
        conversation_state: ConversationHttpState<C>,
        replay_state: ReplayHttpState,
    ) -> Result<Self, SecureLocalHttpHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
    {
        let protected = Router::new()
            .merge(runtime_profile_session_router(
                runtime_profile_state.clone(),
            ))
            .merge(task_run_router(task_run_state))
            .merge(conversation_router(conversation_state))
            .merge(replay_router(replay_state));
        Self::with_protected_router(
            health_state,
            admission_state,
            local_session_service,
            binding,
            clock,
            runtime_profile_state,
            protected,
        )
    }

    /// Consumes the host into an opaque HTTP service for the crate-owned TLS
    /// accept loop. It is intentionally unavailable to external crates.
    #[allow(dead_code)] // Task 4B moves the daemon TLS accept loop to this boundary.
    pub(crate) fn into_service(
        self,
    ) -> impl tower::Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone
    {
        self.router
    }

    fn with_protected_router(
        health_state: HealthState,
        admission_state: AdmissionState,
        local_session_service: Arc<Mutex<gocode_application::local_session::LocalSessionService>>,
        binding: gocode_api::RuntimeSessionBinding,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        runtime_profile_state: RuntimeProfileHttpState,
        protected: Router,
    ) -> Result<Self, SecureLocalHttpHostError> {
        if runtime_profile_state.ordered_capability_digest()
            != *binding.stable().capability_digest()
        {
            return Err(SecureLocalHttpHostError::CapabilityDigestMismatch);
        }
        let local_session_state = LocalSessionHttpState::new(
            local_session_service,
            Arc::clone(&clock),
            VerifiedLocalTls::from_verified_listener(),
        );
        let protected = protected
            .layer(axum_mw::from_fn_with_state(
                admission_state,
                admission_middleware,
            ))
            .layer(SessionAuthLayer::new(
                local_session_state.service(),
                binding,
                clock,
            ))
            .layer(axum_mw::from_fn(request_id_middleware));
        Ok(Self {
            router: Router::new()
                .merge(health_router(health_state))
                .merge(create_local_session_bootstrap_router(local_session_state))
                .merge(protected),
        })
    }

    #[cfg(test)]
    fn router_for_test(&self) -> Router {
        self.router.clone()
    }
}

/// Builds the production canonical HTTP surface.
///
/// `/health` remains unauthenticated. Every `/v1/task-runs/*` route is wrapped
/// by one request identity, bearer authentication, and admission gating.
pub fn create_router<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    let protected = protected_task_run_router(token, admission_state, task_run_state);
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

/// Builds the production canonical TaskRun and Conversation message surface.
pub fn create_router_with_conversations<T, C>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<T>,
    conversation_state: ConversationHttpState<C>,
    runtime_profile_state: RuntimeProfileHttpState,
    replay_state: ReplayHttpState,
) -> Router
where
    T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
    C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
{
    let protected = Router::new()
        .merge(runtime_profile_router(runtime_profile_state))
        .merge(task_run_router(task_run_state))
        .merge(conversation_router(conversation_state))
        .merge(replay_router(replay_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

/// Builds the canonical surface plus the pinned OpenCode V1 compatibility
/// routes under the same protection contour.
pub fn create_router_with_opencode<T, O>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<T>,
    opencode_state: OpenCodeSessionState<O>,
) -> Router
where
    T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
    O: gocode_opencode_compat::SessionV1HostPort + 'static,
{
    let protected = Router::new()
        .merge(task_run_router(task_run_state))
        .merge(opencode_session_router(opencode_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

fn protected_task_run_router<H>(
    token: [u8; 32],
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    task_run_router(task_run_state)
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use gocode_api::{ApiPrincipalId, DaemonInstanceId, StableRuntimeBinding};
    use gocode_application::local_session::{LocalSessionService, bootstrap_proof_transcript};
    use gocode_domain::{event::Sensitivity, id::EventLogLineageId};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    const CAPABILITIES: &[&str] = &["conversation.create.v1", "conversation.list.v1"];

    fn binding() -> gocode_api::RuntimeSessionBinding {
        gocode_api::RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
                ApiPrincipalId::new("local-owner").unwrap(),
                "018f2e3a-7000-7000-8000-000000000003"
                    .parse::<EventLogLineageId>()
                    .unwrap(),
                "gocode-ui-client/1",
                [3; 32],
                crate::runtime_profile::ordered_capability_digest(CAPABILITIES),
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

    fn clock() -> Arc<dyn Fn() -> Duration + Send + Sync> {
        Arc::new(|| Duration::ZERO)
    }

    fn profile_state() -> RuntimeProfileHttpState {
        RuntimeProfileHttpState::new("legacy", "legacy", "0.1.0-test", CAPABILITIES)
    }

    fn host() -> SecureLocalHttpHost {
        let binding = binding();
        let service = Arc::new(Mutex::new(LocalSessionService::new(
            binding.clone(),
            [7; 32],
        )));
        SecureLocalHttpHost::with_protected_router(
            HealthState {
                recovery_state: crate::health::RecoveryState::Ready,
            },
            AdmissionState::new(crate::health::RecoveryState::Ready),
            service,
            binding,
            clock(),
            profile_state(),
            runtime_profile_session_router(profile_state()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn sealed_host_contour_shares_bootstrap_service_with_profile_auth() {
        let app = host().router_for_test();
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/runtime/profile")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let client_nonce = [9; 32];
        let server_nonce = [8; 32];
        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "clientNonce": URL_SAFE_NO_PAD.encode(client_nonce),
                            "serverNonce": URL_SAFE_NO_PAD.encode(server_nonce),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge: serde_json::Value =
            serde_json::from_slice(&to_bytes(challenge.into_body(), 8192).await.unwrap()).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
        mac.update(&bootstrap_proof_transcript(
            &binding(),
            server_nonce,
            client_nonce,
        ));
        let authority = [10; 32];
        let authenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/authenticate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challengeId": challenge["challengeId"],
                            "proof": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
                            "authority": URL_SAFE_NO_PAD.encode(authority),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);
        let profile = app
            .oneshot(
                Request::builder()
                    .uri("/v1/runtime/profile")
                    .header(
                        "authorization",
                        format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority)),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(profile.status(), StatusCode::OK);
    }
}
