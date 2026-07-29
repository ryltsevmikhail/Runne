//! TLS-only HTTP bootstrap endpoints for local runtime sessions.

use std::sync::{Arc, Mutex};

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
pub struct LocalSessionHttpState {
    service: Arc<Mutex<LocalSessionService>>,
    tls_verified: bool,
}
impl LocalSessionHttpState {
    /// Creates a bootstrap route state. `tls_verified` must be true only behind the pinned local TLS listener.
    pub fn new(service: LocalSessionService, tls_verified: bool) -> Self {
        Self {
            service: Arc::new(Mutex::new(service)),
            tls_verified,
        }
    }

    /// Shares the bounded service with a composable session-auth layer.
    pub fn service(&self) -> Arc<Mutex<LocalSessionService>> {
        self.service.clone()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeRequest {
    client_nonce: String,
    server_nonce: String,
    now_millis: u64,
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
    now_millis: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateResponse {
    expires_at_monotonic_millis: u64,
}

/// Builds the two bounded bootstrap endpoints. The caller must mount this router only on TLS.
pub fn local_session_router(state: LocalSessionHttpState) -> Router {
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
    if !state.tls_verified {
        return unavailable();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            let response = error.into_response();
            return if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
                response
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
            service.issue_challenge(
                client_nonce,
                server_nonce,
                std::time::Duration::from_millis(body.now_millis),
            )
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
    if !state.tls_verified {
        return unavailable();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            let response = error.into_response();
            return if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
                response
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
                std::time::Duration::from_millis(body.now_millis),
            )
        });
    match result {
        Ok(value) => Json(AuthenticateResponse {
            expires_at_monotonic_millis: u64::try_from(value.expires_at_monotonic.as_millis())
                .unwrap_or(u64::MAX),
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
