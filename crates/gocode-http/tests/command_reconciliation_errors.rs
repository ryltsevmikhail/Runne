use axum::body::{Body, to_bytes};
use gocode_api::{
    CommandReconciliationContext, CommandReconciliationDisposition, CommandReconciliationHostError,
    CommandReconciliationHostPort, CommandReconciliationWitness,
};
use gocode_http::{
    admission::AdmissionState,
    command_reconciliation::CommandReconciliationHttpState,
    health::{HealthState, RecoveryState},
    router::create_router_with_command_reconciliation,
};
use http::{Method, Request, StatusCode};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const BODY: &str = r#"{"operation":"archive_project","projectId":"018f2e3a-7000-7000-8000-000000000302","expectedVersion":1}"#;

#[derive(Clone, Copy)]
enum ResultKind {
    Indeterminate,
    Error(CommandReconciliationHostError),
}

#[derive(Clone)]
struct Host(ResultKind);

impl CommandReconciliationHostPort for Host {
    async fn reconcile_command(
        &self,
        _: CommandReconciliationContext,
        _: CommandReconciliationWitness,
    ) -> Result<CommandReconciliationDisposition, CommandReconciliationHostError> {
        match self.0 {
            ResultKind::Indeterminate => Ok(CommandReconciliationDisposition::indeterminate()),
            ResultKind::Error(error) => Err(error),
        }
    }
}

fn app(kind: ResultKind) -> axum::Router {
    create_router_with_command_reconciliation(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        CommandReconciliationHttpState::new(Host(kind)),
    )
}

fn request(method: Method) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri("/v1/commands/reconcile")
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .header("x-command-id", "018f2e3a-7000-7000-8000-000000000301")
        .header("idempotency-key", "reconcile-test")
        .header("content-type", "application/json")
        .body(Body::from(BODY))
        .unwrap()
}

#[tokio::test]
async fn indeterminate_and_closed_host_errors_preserve_bodies_and_no_store() {
    let response = app(ResultKind::Indeterminate)
        .oneshot(request(Method::POST))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap(),
        r#"{"disposition":"indeterminate"}"#
    );

    for (error, status, code) in [
        (
            CommandReconciliationHostError::Conflict,
            StatusCode::CONFLICT,
            "command_conflict",
        ),
        (
            CommandReconciliationHostError::Backpressure,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_backpressure",
        ),
        (
            CommandReconciliationHostError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
        ),
        (
            CommandReconciliationHostError::InvariantViolation,
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    ] {
        let response = app(ResultKind::Error(error))
            .oneshot(request(Method::POST))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let request_id = response.headers()["x-request-id"]
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

    let response = app(ResultKind::Indeterminate)
        .oneshot(request(Method::GET))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"code": "method_not_allowed", "requestId": request_id})
    );
}
