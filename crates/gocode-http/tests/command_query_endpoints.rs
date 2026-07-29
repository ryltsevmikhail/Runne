//! Integration tests for command and query endpoints, plus the
//! combined application router.

use axum::body::{Body, to_bytes};
use gocode_http::admission::AdmissionState;
use gocode_http::health::{HealthState, RecoveryState};
use gocode_http::limits::LimitsConfig;
use gocode_http::replay::ReplayState;
use gocode_http::router::create_router;
use http::{Request, StatusCode};
use std::sync::Arc;

use tower::ServiceExt;

// ── Helpers ─────────────────────────────────────────────────────────────

const TOKEN: [u8; 32] = [0xABu8; 32];

/// Build the full application router with `C = ()`, `Q = ()`, `R = ()`.
fn make_app() -> axum::Router {
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

/// Build an authenticated GET request.
fn authed_get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("GET")
        .header("Authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .body(Body::empty())
        .unwrap()
}

/// Read the full response body as a `serde_json::Value`.
async fn read_body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Tests: Command endpoints ────────────────────────────────────────────

#[tokio::test]
async fn create_session_returns_202() {
    let app = make_app();
    let req = authed_post(
        "/commands/create-session",
        r#"{"workspace_id":"ws-1","profile_id":null}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = read_body_json(response).await;
    assert!(json.get("session_id").and_then(|v| v.as_str()).is_some());
    assert_eq!(json["status"], "created");
}

#[tokio::test]
async fn prompt_returns_202() {
    let app = make_app();
    let req = authed_post(
        "/commands/prompt",
        r#"{"message":"hello","attachments":null}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = read_body_json(response).await;
    assert!(json.get("taskrun_id").and_then(|v| v.as_str()).is_some());
    assert_eq!(json["status"], "accepted");
}

#[tokio::test]
async fn abort_session_returns_202() {
    let app = make_app();
    let req = authed_post("/commands/abort", r#"{"reason":"test"}"#);
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = read_body_json(response).await;
    assert_eq!(json["status"], "aborted");
}

#[tokio::test]
async fn create_task_run_returns_202() {
    let app = make_app();
    let req = authed_post(
        "/commands/create-task-run",
        r#"{"task_type":"test","input":{}}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = read_body_json(response).await;
    assert!(json.get("taskrun_id").and_then(|v| v.as_str()).is_some());
}

#[tokio::test]
async fn complete_task_run_returns_202() {
    let app = make_app();
    let req = authed_post(
        "/commands/complete-task-run",
        r#"{"outcome":"success","output":null}"#,
    );
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = read_body_json(response).await;
    assert!(json.get("taskrun_id").and_then(|v| v.as_str()).is_some());
    assert_eq!(json["status"], "completed");
}

// ── Tests: Query endpoints ──────────────────────────────────────────────

#[tokio::test]
async fn session_status_returns_200() {
    let app = make_app();
    let req = authed_get("/queries/session/sess-001");
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert_eq!(json["session_id"], "sess-001");
    assert_eq!(json["status"], "active");
    assert_eq!(json["task_count"], 0);
}

#[tokio::test]
async fn task_run_status_returns_200() {
    let app = make_app();
    let req = authed_get("/queries/task-run/tr-001");
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert_eq!(json["taskrun_id"], "tr-001");
    assert_eq!(json["state"], "created");
    assert!(json["events"].as_array().is_some());
}

// ── Tests: Auth and combined router ─────────────────────────────────────

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let app = make_app();
    let req = Request::builder()
        .uri("/commands/create-session")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"workspace_id":"ws-1"}"#))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn full_router_health_works() {
    let app = make_app();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_body_json(response).await;
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn authenticated_prompt_with_invalid_json_returns_400() {
    // Axum's Json extractor returns 400 for syntactically malformed JSON.
    let app = make_app();
    let req = authed_post("/commands/prompt", "not json");
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
