use axum::body::Body;
use http::{Request, StatusCode};
use tower::ServiceExt;

use super::{ID, app, authorized};

#[tokio::test]
async fn rename_rejects_untrusted_body_version_and_missing_command_identity() {
    for (body, command_id) in [
        (r#"{"expectedVersion":1,"displayName":"Renamed","extra":true}"#, true),
        (r#"{"expectedVersion":0,"displayName":"Renamed"}"#, true),
        (r#"{"expectedVersion":1,"displayName":"Renamed"}"#, false),
    ] {
        let mut request = authorized(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/projects/{ID}/rename")),
        )
        .header("idempotency-key", "rename-project")
        .header("content-type", "application/json");
        if command_id {
            request = request.header("x-command-id", ID);
        }
        let response = app().oneshot(request.body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().contains_key("x-request-id"));
    }
}
