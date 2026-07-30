//! TLS-only HTTP bootstrap endpoints for local runtime sessions.

#![allow(dead_code)] // Used by the crate-owned TLS serving boundary in Task 4B.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_application::local_session::{BootstrapProof, LocalSessionError, LocalSessionService};
use serde::{Deserialize, Serialize};

use crate::error::{RequestId, canonical_error_response};

const MAX_LOCAL_SESSION_BODY_BYTES: usize = 8 * 1024;

/// State for bootstrap routes, restricted to an already verified TLS listener.
#[derive(Clone)]
pub(crate) struct LocalSessionHttpState {
    service: Arc<Mutex<LocalSessionService>>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    _verified_tls: VerifiedLocalTls,
}

/// Capability minted only by verified local-TLS listener composition.
#[derive(Clone)]
pub(crate) struct VerifiedLocalTls(());

impl VerifiedLocalTls {
    #[allow(dead_code)] // Constructed by the verified listener in Task 4.
    pub(crate) const fn from_verified_listener() -> Self {
        Self(())
    }
}

impl LocalSessionHttpState {
    /// Creates bootstrap state after the pinned local TLS listener has verified its identity.
    #[allow(dead_code)] // Constructed by the verified listener in Task 4.
    pub(crate) fn new(
        service: Arc<Mutex<LocalSessionService>>,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        verified_tls: VerifiedLocalTls,
    ) -> Self {
        Self {
            service,
            clock,
            _verified_tls: verified_tls,
        }
    }

    /// Shares the bounded service with a composable session-auth layer.
    pub(crate) fn service(&self) -> Arc<Mutex<LocalSessionService>> {
        self.service.clone()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeRequest {
    client_nonce: String,
    server_nonce: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge_id: String,
    server_nonce: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticateRequest {
    challenge_id: String,
    proof: String,
    authority: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateResponse {
    expires_at_monotonic_millis: u64,
    session_id: String,
}

/// Builds the two bounded bootstrap endpoints. The caller must mount this router only on TLS.
pub(crate) fn local_session_router(state: LocalSessionHttpState) -> Router {
    Router::new()
        .route("/v1/local-session/challenges", post(challenge))
        .route("/v1/local-session/authenticate", post(authenticate))
        .layer(DefaultBodyLimit::max(MAX_LOCAL_SESSION_BODY_BYTES))
        .with_state(state)
}

async fn challenge(
    State(state): State<LocalSessionHttpState>,
    body: Result<Json<ChallengeRequest>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            let response = error.into_response();
            return if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
                payload_too_large()
            } else {
                invalid_request()
            };
        }
    };
    let (Some(client_nonce), Some(server_nonce)) =
        (decode_32(&body.client_nonce), decode_32(&body.server_nonce))
    else {
        return invalid_request();
    };
    let result = state
        .service
        .lock()
        .map_err(|_| LocalSessionError::Unavailable)
        .and_then(|mut service| {
            service.issue_challenge(client_nonce, server_nonce, (state.clock)())
        });
    match result {
        Ok(value) => Json(ChallengeResponse {
            challenge_id: URL_SAFE_NO_PAD.encode(value.id.0),
            server_nonce: URL_SAFE_NO_PAD.encode(value.server_nonce),
        })
        .into_response(),
        Err(LocalSessionError::Unavailable) => unavailable(),
        Err(LocalSessionError::Unauthorized) => unauthorized(),
    }
}

async fn authenticate(
    State(state): State<LocalSessionHttpState>,
    body: Result<Json<AuthenticateRequest>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            let response = error.into_response();
            return if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
                payload_too_large()
            } else {
                invalid_request()
            };
        }
    };
    let (Some(id), Some(proof), Some(authority)) = (
        decode_16(&body.challenge_id),
        decode_32(&body.proof),
        decode_32(&body.authority),
    ) else {
        return unauthorized();
    };
    let result = state
        .service
        .lock()
        .map_err(|_| LocalSessionError::Unavailable)
        .and_then(|mut service| {
            service.authenticate(
                gocode_application::local_session::LocalSessionChallengeId(id),
                BootstrapProof::new(proof),
                authority,
                (state.clock)(),
            )
        });
    match result {
        Ok(value) => Json(AuthenticateResponse {
            expires_at_monotonic_millis: u64::try_from(value.expires_at_monotonic.as_millis())
                .unwrap_or(u64::MAX),
            session_id: hex::encode(value.binding.ephemeral().session_id()),
        })
        .into_response(),
        Err(LocalSessionError::Unavailable) => unavailable(),
        Err(LocalSessionError::Unauthorized) => unauthorized(),
    }
}

fn decode_32(value: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}
fn decode_16(value: &str) -> Option<[u8; 16]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}
fn unauthorized() -> Response {
    canonical_error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        &RequestId::generate(),
    )
}
fn unavailable() -> Response {
    canonical_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "local_session_unavailable",
        &RequestId::generate(),
    )
}
fn invalid_request() -> Response {
    canonical_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &RequestId::generate(),
    )
}
fn payload_too_large() -> Response {
    canonical_error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "invalid_request",
        &RequestId::generate(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use gocode_api::{
        ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding,
    };
    use gocode_application::local_session::bootstrap_proof_transcript;
    use gocode_domain::{event::Sensitivity, id::EventLogLineageId};
    use hmac::{Hmac, Mac};
    use tower::ServiceExt;

    async fn assert_canonical_error(response: Response, status: StatusCode, code: &str) {
        assert_eq!(response.status(), status);
        let request_id = response
            .headers()
            .get("x-request-id")
            .expect("canonical error must include request identity")
            .to_str()
            .unwrap()
            .to_owned();
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"code": code, "requestId": request_id})
        );
    }

    fn state() -> LocalSessionHttpState {
        LocalSessionHttpState::new(
            Arc::new(Mutex::new(LocalSessionService::new(binding(), [7; 32]))),
            Arc::new(|| Duration::ZERO),
            VerifiedLocalTls::from_verified_listener(),
        )
    }

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
                [4; 32],
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
    async fn verified_tls_router_issues_and_consumes_a_challenge() {
        let now = Arc::new(Mutex::new(Duration::ZERO));
        let clock = {
            let now = now.clone();
            Arc::new(move || *now.lock().unwrap()) as Arc<dyn Fn() -> Duration + Send + Sync>
        };
        let state = LocalSessionHttpState::new(
            Arc::new(Mutex::new(LocalSessionService::new(binding(), [7; 32]))),
            clock,
            VerifiedLocalTls::from_verified_listener(),
        );
        let app = local_session_router(state);
        let client = URL_SAFE_NO_PAD.encode([9; 32]);
        let server = URL_SAFE_NO_PAD.encode([8; 32]);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/local-session/challenges")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"clientNonce":client,"serverNonce":server}).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let dto: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(dto["serverNonce"], URL_SAFE_NO_PAD.encode([8; 32]));
        assert!(dto["challengeId"].is_string());
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&[7; 32]).unwrap();
        mac.update(&bootstrap_proof_transcript(&binding(), [8; 32], [9; 32]));
        let payload = serde_json::json!({"challengeId":dto["challengeId"],"proof":URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),"authority":URL_SAFE_NO_PAD.encode([10;32])});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/authenticate")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let authenticated: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            authenticated,
            serde_json::json!({
                "expiresAtMonotonicMillis": 600_000,
                "sessionId": hex::encode(binding().ephemeral().session_id()),
            })
        );
        let replay = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/authenticate")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert!(
            std::str::from_utf8(&to_bytes(replay.into_body(), 4096).await.unwrap())
                .unwrap()
                .contains("unauthorized")
        );
    }

    #[tokio::test]
    async fn verified_tls_router_rejects_unknown_challenge_fields_with_canonical_json() {
        let response = local_session_router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "clientNonce": URL_SAFE_NO_PAD.encode([9; 32]),
                            "serverNonce": URL_SAFE_NO_PAD.encode([8; 32]),
                            "unexpected": true,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_canonical_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }

    #[tokio::test]
    async fn verified_tls_router_rejects_unknown_authentication_fields_with_canonical_json() {
        let response = local_session_router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/authenticate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challengeId": URL_SAFE_NO_PAD.encode([1; 16]),
                            "proof": URL_SAFE_NO_PAD.encode([2; 32]),
                            "authority": URL_SAFE_NO_PAD.encode([3; 32]),
                            "unexpected": true,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_canonical_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }

    #[tokio::test]
    async fn verified_tls_router_rejects_bodies_larger_than_eight_kib_with_canonical_json() {
        let response = local_session_router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from("x".repeat(MAX_LOCAL_SESSION_BODY_BYTES + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_canonical_error(response, StatusCode::PAYLOAD_TOO_LARGE, "invalid_request").await;
    }

    #[tokio::test]
    async fn verified_tls_router_maps_challenge_exhaustion_to_canonical_unavailable() {
        let app = local_session_router(state());
        for value in 0..32_u8 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/local-session/challenges")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({
                                "clientNonce": URL_SAFE_NO_PAD.encode([value; 32]),
                                "serverNonce": URL_SAFE_NO_PAD.encode([value.wrapping_add(32); 32]),
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "clientNonce": URL_SAFE_NO_PAD.encode([64; 32]),
                            "serverNonce": URL_SAFE_NO_PAD.encode([96; 32]),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_canonical_error(
            response,
            StatusCode::SERVICE_UNAVAILABLE,
            "local_session_unavailable",
        )
        .await;
    }
}
