use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::body::{Body, to_bytes};
use bytes::Bytes;
use http::{HeaderValue, Request, StatusCode};
use runne_api::{
    CommandReconciliationContext, CommandReconciliationDisposition, CommandReconciliationHostError,
    CommandReconciliationHostPort, CommandReconciliationWitness,
};
use runne_http::{
    admission::AdmissionState,
    command_reconciliation::CommandReconciliationHttpState,
    health::{HealthState, RecoveryState},
    router::create_router_with_command_reconciliation,
};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000301";
const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const VALID: &str = r#"{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","expectedVersion":1}"#;

#[derive(Clone)]
struct Host(Arc<AtomicUsize>);

impl CommandReconciliationHostPort for Host {
    async fn reconcile_command(
        &self,
        _: CommandReconciliationContext,
        _: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(CommandReconciliationDisposition::not_committed_retryable())
    }
}

fn app(calls: Arc<AtomicUsize>, recovery: RecoveryState) -> axum::Router {
    create_router_with_command_reconciliation(
        TOKEN,
        HealthState {
            recovery_state: recovery.clone(),
        },
        AdmissionState::new(recovery),
        CommandReconciliationHttpState::new(Host(calls)),
    )
}

fn request(body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/commands/reconcile")
        .header("x-command-id", COMMAND)
        .header("idempotency-key", "reconcile-test")
        .header("content-type", "application/json")
        .body(body.into())
        .unwrap()
}

fn authorize(request: &mut Request<Body>) {
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", hex::encode(TOKEN)).parse().unwrap(),
    );
}

async fn assert_canonical(response: axum::response::Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"code": code, "requestId": request_id})
    );
}

#[tokio::test]
async fn authentication_precedes_every_body_and_admission_rejection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let limit = runne_api::max_message_text_bytes() + 4 * 1024;
    let streamed = Body::from_stream(futures::stream::once(async move {
        Ok::<_, Infallible>(Bytes::from(vec![b'x'; limit + 1]))
    }));
    let cases = [
        (request(Body::from("{")), RecoveryState::Ready),
        (
            request(Body::from(format!(
                r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1,"unknown":true}}"#
            ))),
            RecoveryState::Ready,
        ),
        (
            request(Body::from(format!(
                r#"{{"operation":"archive_project","projectId":"{PROJECT}","projectId":"{PROJECT}","expectedVersion":1}}"#
            ))),
            RecoveryState::Ready,
        ),
        (
            request(Body::from(r#"{"operation":"archive_project"}"#)),
            RecoveryState::Ready,
        ),
        (
            {
                let mut value = request(Body::from(VALID));
                value
                    .headers_mut()
                    .insert("content-length", (limit + 1).into());
                value
            },
            RecoveryState::Ready,
        ),
        (request(streamed), RecoveryState::Ready),
        (request(Body::from(VALID)), RecoveryState::IntegrityBlocked),
    ];
    for (request, recovery) in cases {
        let response = app(calls.clone(), recovery).oneshot(request).await.unwrap();
        assert_canonical(response, StatusCode::UNAUTHORIZED, "unauthorized").await;
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn authenticated_malformed_and_authority_fields_are_closed_invalid_requests() {
    let calls = Arc::new(AtomicUsize::new(0));
    let bodies = [
        "{".to_owned(),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1,"unknown":true}}"#
        ),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","projectId":"{PROJECT}","expectedVersion":1}}"#
        ),
        r#"{"operation":"archive_project"}"#.to_owned(),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","workspaceId":"{PROJECT}","expectedVersion":1}}"#
        ),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1,"authority":"secret"}}"#
        ),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1,"principal":"other"}}"#
        ),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1,"fingerprint":"00"}}"#
        ),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":1,"rootAdmission":"token"}}"#
        ),
        r#"{"operation":"archive_project","projectId":"not-a-uuid","expectedVersion":1}"#
            .to_owned(),
        format!(
            r#"{{"operation":"archive_project","projectId":"{PROJECT}","expectedVersion":0}}"#
        ),
        format!(
            r#"{{"operation":"create_project","projectId":"{PROJECT}","displayName":""}}"#
        ),
        r#"{"operation":"generate_conversation_text","conversationId":"018f2e3a-7000-7000-8000-000000000303","expectedVersion":1,"text":""}"#.to_owned(),
        r#"{"operation":"bind_workspace_root","workspaceId":"018f2e3a-7000-7000-8000-000000000303","expectedVersion":1,"admissionDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.to_owned(),
        format!(
            r#"{{"operation":"archive_project","project_id":"{PROJECT}","expectedVersion":1}}"#
        ),
    ];
    for body in bodies {
        let mut request = request(Body::from(body));
        authorize(&mut request);
        let response = app(calls.clone(), RecoveryState::Ready)
            .oneshot(request)
            .await
            .unwrap();
        assert_canonical(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }
    let mut wrong_content_type = request(Body::from(VALID));
    authorize(&mut wrong_content_type);
    wrong_content_type
        .headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    let response = app(calls.clone(), RecoveryState::Ready)
        .oneshot(wrong_content_type)
        .await
        .unwrap();
    assert_canonical(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn identity_header_and_body_limits_fail_before_the_host() {
    let calls = Arc::new(AtomicUsize::new(0));
    for header in ["x-command-id", "idempotency-key"] {
        let mut duplicate = request(Body::from(VALID));
        authorize(&mut duplicate);
        duplicate
            .headers_mut()
            .append(header, HeaderValue::from_static("duplicate"));
        let response = app(calls.clone(), RecoveryState::Ready)
            .oneshot(duplicate)
            .await
            .unwrap();
        assert_canonical(response, StatusCode::BAD_REQUEST, "invalid_request").await;

        let mut malformed = request(Body::from(VALID));
        authorize(&mut malformed);
        malformed
            .headers_mut()
            .insert(header, HeaderValue::from_bytes(&[0xff]).unwrap());
        let response = app(calls.clone(), RecoveryState::Ready)
            .oneshot(malformed)
            .await
            .unwrap();
        assert_canonical(response, StatusCode::BAD_REQUEST, "invalid_request").await;

        let mut missing = request(Body::from(VALID));
        authorize(&mut missing);
        missing.headers_mut().remove(header);
        let response = app(calls.clone(), RecoveryState::Ready)
            .oneshot(missing)
            .await
            .unwrap();
        assert_canonical(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }
    let limit = runne_api::max_message_text_bytes() + 4 * 1024;
    let mut declared = request(Body::from(VALID));
    authorize(&mut declared);
    declared
        .headers_mut()
        .insert("content-length", (limit + 1).into());
    let response = app(calls.clone(), RecoveryState::Ready)
        .oneshot(declared)
        .await
        .unwrap();
    assert_canonical(response, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large").await;

    let streamed = Body::from_stream(futures::stream::once(async move {
        Ok::<_, Infallible>(Bytes::from(vec![b'x'; limit + 1]))
    }));
    let mut streamed = request(streamed);
    authorize(&mut streamed);
    let response = app(calls.clone(), RecoveryState::Ready)
        .oneshot(streamed)
        .await
        .unwrap();
    assert_canonical(response, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large").await;

    let mut blocked = request(Body::from(VALID));
    authorize(&mut blocked);
    let response = app(calls.clone(), RecoveryState::IntegrityBlocked)
        .oneshot(blocked)
        .await
        .unwrap();
    assert_canonical(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "runtime_unavailable",
    )
    .await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}
