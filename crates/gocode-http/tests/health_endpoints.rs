//! Integration tests for health endpoint and admission middleware.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use gocode_http::admission::{self, AdmissionState};
use gocode_http::health::{self, HealthState, RecoveryState};
use tower::ServiceExt;

// ── Helpers ───────────────────────────────────────────────────────────

/// A dummy handler that returns 200 OK.
async fn dummy_handler() -> &'static str {
    "ok"
}

/// Build a router with admission middleware wrapping a dummy handler.
fn make_admission_router(state: AdmissionState) -> Router {
    Router::new()
        .route("/", get(dummy_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admission::admission_middleware,
        ))
        .with_state(state)
}

// ── Health endpoint tests ─────────────────────────────────────────────

#[tokio::test]
async fn health_ready_returns_200() {
    let state = HealthState {
        recovery_state: RecoveryState::Ready,
    };
    let app = health::health_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn health_recovery_blocked_returns_200_degraded() {
    let state = HealthState {
        recovery_state: RecoveryState::RecoveryBlocked,
    };
    let app = health::health_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "degraded");
}

#[tokio::test]
async fn health_integrity_blocked_returns_503() {
    let state = HealthState {
        recovery_state: RecoveryState::IntegrityBlocked,
    };
    let app = health::health_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "unavailable");
}

#[tokio::test]
async fn health_shutting_down_returns_503() {
    let state = HealthState {
        recovery_state: RecoveryState::ShuttingDown,
    };
    let app = health::health_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "shutting_down");
}

#[tokio::test]
async fn health_includes_version() {
    let state = HealthState {
        recovery_state: RecoveryState::Ready,
    };
    let app = health::health_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("version").is_some());
}

// ── Admission middleware tests ─────────────────────────────────────────

#[tokio::test]
async fn admission_blocks_when_integrity_blocked() {
    let state = AdmissionState::new(RecoveryState::IntegrityBlocked);
    let app = make_admission_router(state);

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn admission_blocks_when_shutting_down() {
    let state = AdmissionState::new(RecoveryState::ShuttingDown);
    let app = make_admission_router(state);

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn admission_allows_when_ready() {
    let state = AdmissionState::new(RecoveryState::Ready);
    let app = make_admission_router(state);

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn admission_allows_when_recovery_blocked() {
    let state = AdmissionState::new(RecoveryState::RecoveryBlocked);
    let app = make_admission_router(state);

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_endpoint_always_available() {
    // Health endpoint is served on its own router without admission
    // middleware, so it should return 200 even when the overall state
    // would be IntegrityBlocked.
    let state = HealthState {
        recovery_state: RecoveryState::IntegrityBlocked,
    };
    let app = health::health_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Health reports the state but never returns 503 from the middleware
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // The health handler itself returns 503 for IntegrityBlocked,
    // but there is no admission middleware preventing the call.
    assert_eq!(json["status"], "unavailable");
}

#[tokio::test]
async fn admission_state_update_reflected() {
    let state = AdmissionState::new(RecoveryState::Ready);
    let app = make_admission_router(state.clone());

    // Initially allows.
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Update to IntegrityBlocked — should block.
    state.update(RecoveryState::IntegrityBlocked);

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Update back to Ready — should allow again.
    state.update(RecoveryState::Ready);

    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
