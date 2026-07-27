//! Integration tests for replay endpoints.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use gocode_http::admission::AdmissionState;
use gocode_http::health::{HealthState, RecoveryState};
use gocode_http::limits::LimitsConfig;
use gocode_http::replay::{self, ReplayState};
use gocode_http::router::create_router;
use std::sync::Arc;
use tower::ServiceExt;

// ── Helpers ─────────────────────────────────────────────────────────────

const TOKEN: [u8; 32] = [0xABu8; 32];

/// Build an authenticated POST request with JSON body.
fn authed_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// Build an unauthenticated POST request with JSON body.
fn unauthed_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// Read the full response body as a `serde_json::Value`.
async fn read_body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Build a replay-only router wrapped in auth + admission layers
/// so we can test both replay logic and auth/admission gating together.
fn make_protected_replay_router() -> axum::Router {
    let replay_state = ReplayState {
        service: Arc::new(()),
        limits: LimitsConfig::default(),
    };

    let admission_state = AdmissionState::new(RecoveryState::Ready);
    let auth_layer = gocode_http::auth::AuthLayer::new(TOKEN);

    axum::Router::new()
        .merge(replay::replay_router(replay_state))
        .layer(axum::middleware::from_fn_with_state(
            admission_state,
            gocode_http::admission::admission_middleware,
        ))
        .layer(auth_layer)
}

/// Build the full application router with replay.
fn make_full_app() -> axum::Router {
    let health_state = HealthState {
        recovery_state: RecoveryState::Ready,
    };
    let admission_state = AdmissionState::new(RecoveryState::Ready);
    let replay_state = ReplayState {
        service: Arc::new(()),
        limits: LimitsConfig::default(),
    };
    create_router::<(), (), ()>(TOKEN, health_state, admission_state, replay_state)
}

// ── Tests: Replay endpoint success cases ─────────────────────────────────

#[tokio::test]
async fn open_session_returns_session_id() {
    let app = make_protected_replay_router();
    let req = authed_post(
        "/replay/open-session",
        r#"{"principal_id":"p1","session_generation":1,"authority_id":"aa","authorization_epoch":1,"aggregate_type":0,"aggregate_id":"00000000000000000000000000000000"}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert!(json.get("session_id").and_then(|v| v.as_str()).is_some());
    assert!(
        json.get("high_water_ref")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(json["events"].as_array().is_some());
}

#[tokio::test]
async fn read_page_returns_empty() {
    let app = make_protected_replay_router();
    let req = authed_post("/replay/sess-001/read-page", r#"{"limit":10}"#);
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert!(json["events"].as_array().is_some());
    assert_eq!(json["has_more"], false);
}

#[tokio::test]
async fn complete_catch_up_returns_proof() {
    let app = make_protected_replay_router();
    let req = authed_post(
        "/replay/sess-001/complete-catch-up",
        r#"{"catch_up_proof":"proof"}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert!(
        json.get("catch_up_proof")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert_eq!(json["session_state"], "catch_up_complete");
}

#[tokio::test]
async fn continue_live_returns_live_id() {
    let app = make_protected_replay_router();
    let req = authed_post("/replay/sess-001/continue-live", r#"{}"#);
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert!(
        json.get("live_delivery_id")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert_eq!(json["session_state"], "live");
}

#[tokio::test]
async fn close_session_returns_204() {
    let app = make_protected_replay_router();
    let req = authed_post("/replay/sess-001/close", r#"{}"#);
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ── Tests: Auth gating ───────────────────────────────────────────────────

#[tokio::test]
async fn replay_endpoints_require_auth() {
    let app = make_protected_replay_router();
    let req = unauthed_post(
        "/replay/open-session",
        r#"{"principal_id":"p1","session_generation":1,"authority_id":"aa","authorization_epoch":1,"aggregate_type":0,"aggregate_id":"00000000000000000000000000000000"}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Tests: Full router integration ───────────────────────────────────────

#[tokio::test]
async fn replay_router_merges_into_full_router() {
    let app = make_full_app();

    // Health still works.
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Replay endpoint works through the full router.
    let req = authed_post(
        "/replay/open-session",
        r#"{"principal_id":"p1","session_generation":1,"authority_id":"aa","authorization_epoch":1,"aggregate_type":0,"aggregate_id":"00000000000000000000000000000000"}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert!(json.get("session_id").and_then(|v| v.as_str()).is_some());
}
