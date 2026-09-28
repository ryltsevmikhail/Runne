use axum::body::{Body, to_bytes};
use http::{Request, StatusCode};
use tower::ServiceExt;

use super::{ID, app, authorized};

#[tokio::test]
async fn project_creation_rejects_forged_trust_payload_fields() {
    let response = authorized(Request::builder().method("POST").uri("/v1/projects"))
        .header("x-command-id", ID)
        .header("idempotency-key", "forged-trust")
        .header("content-type", "application/json")
        .header("x-project-trusted", "true")
        .body(Body::from(format!(
            r#"{{"projectId":"{ID}","displayName":"name","projectTrusted":true,"trustRevision":999}}"#
        )))
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(!body.contains("projectTrusted"));
    assert!(!body.contains("trustRevision"));
}

#[tokio::test]
async fn project_trust_header_cannot_override_missing_runtime_host() {
    let response = authorized(Request::builder().method("POST").uri("/v1/projects"))
        .header("x-command-id", ID)
        .header("idempotency-key", "header-trust-claim")
        .header("content-type", "application/json")
        .header("x-project-trusted", "true")
        .body(Body::from(format!(
            r#"{{"projectId":"{ID}","displayName":"name"}}"#
        )))
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains(r#""code":"runtime_unavailable""#));
}
