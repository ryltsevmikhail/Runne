//! Integration tests for the auth middleware.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use gocode_http::auth::{AuthLayer, extract_bearer_token};
use tower::ServiceExt;

// ── Helpers ───────────────────────────────────────────────────────────

/// Simple handler that returns 200 OK.
async fn handler() -> &'static str {
    "ok"
}

/// Build an Axum router with the auth layer.
fn make_router(token: [u8; 32]) -> Router {
    Router::new()
        .route("/", get(handler))
        .layer(AuthLayer::new(token))
}

/// Build a GET / request with a Bearer token header.
fn authed_request(token_hex: &str) -> Request<Body> {
    Request::builder()
        .uri("/")
        .header("Authorization", format!("Bearer {token_hex}"))
        .body(Body::empty())
        .unwrap()
}

/// Hex-encode a byte slice without pulling in the `hex` crate.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_token_passes() {
    let token = [0xABu8; 32];
    let app = make_router(token);
    let request = authed_request(&hex_encode(&token));

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_header_returns_401() {
    let token = [0xABu8; 32];
    let app = make_router(token);
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_scheme_returns_401() {
    let token = [0xABu8; 32];
    let app = make_router(token);
    let request = Request::builder()
        .uri("/")
        .header("Authorization", format!("Basic {}", hex_encode(&token)))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_token_returns_401() {
    let token = [0xABu8; 32];
    let app = make_router(token);
    let wrong = [0xCDu8; 32];
    let request = authed_request(&hex_encode(&wrong));

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn short_token_returns_401() {
    let token = [0xABu8; 32];
    let app = make_router(token);
    let short_hex = hex_encode(&[0xABu8; 16]);
    let request = authed_request(&short_hex);

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_hex_token_returns_401() {
    let token = [0xABu8; 32];
    let app = make_router(token);
    let request = Request::builder()
        .uri("/")
        .header("Authorization", "Bearer zzzzzz")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn oversized_bearer_value_is_rejected_before_hex_allocation() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", "ab".repeat(1024)).parse().unwrap(),
    );
    assert_eq!(extract_bearer_token(&headers), None);
}
