use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use super::support::{PATH, Query, QueryOutcome, app};

async fn assert_marker_free_static(response: axum::response::Response, marker: &str) {
    assert!(!format!("{:?}", response.headers()).contains(marker));
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.is_empty());
    assert!(!String::from_utf8_lossy(&body).contains(marker));
}

#[tokio::test]
async fn rejected_http_authorization_body_header_and_endpoint_markers_are_not_reflected() {
    let query = Arc::new(Query::new(QueryOutcome::Available));
    let (app, authorization) = app(Arc::clone(&query));
    let authorization_marker = "task3-authorization-marker";
    let body_marker = "task3-provider-body-marker";
    let header_marker = "task3-raw-error-marker";
    let path_marker = "task3-path-marker";

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header(
                    "authorization",
                    format!("GocodeSession {authorization_marker}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_marker_free_static(unauthorized, authorization_marker).await;

    let body = super::request(app.clone(), &authorization, "GET", Body::from(body_marker)).await;
    assert_eq!(body.status(), StatusCode::BAD_REQUEST);
    assert_marker_free_static(body, body_marker).await;

    let malformed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", authorization.clone())
                .header("content-length", header_marker)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_marker_free_static(malformed, header_marker).await;

    let endpoint = app
        .oneshot(
            Request::builder()
                .uri(format!("{PATH}?{path_marker}"))
                .header("authorization", authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(endpoint.status(), StatusCode::BAD_REQUEST);
    assert_marker_free_static(endpoint, path_marker).await;
    assert_eq!(query.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn http_telemetry_route_stays_protected_and_payload_free() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/operational_telemetry.rs"),
    )
    .unwrap();
    for forbidden in [
        "serde_json::Value",
        "response.bytes()",
        "response.text()",
        "response.json()",
        "gocode_store",
        "gocode_observability",
        "pub fn operational_telemetry_router",
        "HashMap",
        "BTreeMap",
        ": String",
        "source: ",
    ] {
        assert!(!source.contains(forbidden), "contains {forbidden}");
    }
}
