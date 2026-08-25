use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use runne_api::{
    ApiActor, ExistingProcessCommand, ProcessCommandContext, ProcessHostError, ProcessHostPort,
    ProcessOutputPage, ProcessSnapshot, StartProcessCommand,
};
use runne_http::{
    error::RequestId,
    processes::{ProcessHttpState, process_router},
};
use tower::ServiceExt;

const PROCESS: &str = "018f2e3a-7000-7000-8000-000000000306";

#[derive(Clone)]
struct Unavailable;

impl ProcessHostPort for Unavailable {
    async fn start_process(
        &self,
        _: ProcessCommandContext,
        _: StartProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
    async fn get_process(
        &self,
        _: runne_api::ProcessQueryContext,
        _: runne_domain::id::ProcessId,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
    async fn read_process_output(
        &self,
        _: runne_api::ProcessQueryContext,
        _: runne_domain::id::ProcessId,
        _: u64,
        _: u16,
    ) -> Result<ProcessOutputPage, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
    async fn stop_process(
        &self,
        _: ProcessCommandContext,
        _: ExistingProcessCommand,
    ) -> Result<ProcessSnapshot, ProcessHostError> {
        Err(ProcessHostError::Unavailable)
    }
}

#[tokio::test]
async fn process_routes_require_authenticated_owner_for_reads() {
    let app = process_router(ProcessHttpState::new(
        Unavailable,
        ApiActor::new("http-test").unwrap(),
    ));
    let request = Request::builder()
        .uri(format!("/v1/processes/{PROCESS}"))
        .extension(RequestId::bootstrap_rejection())
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body(response).await,
        r#"{"code":"unauthorized","requestId":"00000000-0000-0000-0000-000000000000"}"#
    );
}

#[tokio::test]
async fn process_routes_reject_non_uuidv7_process_ids() {
    let app = process_router(ProcessHttpState::new(
        Unavailable,
        ApiActor::new("http-test").unwrap(),
    ));
    let request = Request::builder()
        .uri("/v1/processes/not-an-id")
        .extension(RequestId::bootstrap_rejection())
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

async fn body(response: Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
