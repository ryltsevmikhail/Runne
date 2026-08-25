use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use runne_api::{
    WorkspaceFileContent, WorkspaceFileHostError, WorkspaceFileHostPort, WorkspaceFileListRequest,
    WorkspaceFilePage, WorkspaceFileQueryContext, WorkspaceFileReadRequest,
};
use runne_http::{
    admission::AdmissionState,
    health::{HealthState, RecoveryState},
    router::create_router_with_workspace_files,
    workspace_files::WorkspaceFileHttpState,
};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const ID: &str = "0198d1a5-0000-7000-8000-000000000001";

#[derive(Clone)]
struct Unavailable;

impl WorkspaceFileHostPort for Unavailable {
    async fn list_files(
        &self,
        _: WorkspaceFileQueryContext,
        _: WorkspaceFileListRequest,
    ) -> Result<WorkspaceFilePage, WorkspaceFileHostError> {
        Err(WorkspaceFileHostError::Unavailable)
    }
    async fn read_file(
        &self,
        _: WorkspaceFileQueryContext,
        _: WorkspaceFileReadRequest,
    ) -> Result<WorkspaceFileContent, WorkspaceFileHostError> {
        Err(WorkspaceFileHostError::Unavailable)
    }
}

fn app() -> axum::Router {
    create_router_with_workspace_files(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        WorkspaceFileHttpState::new(Unavailable),
    )
}

fn authorized(request: http::request::Builder) -> http::request::Builder {
    request.header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
}

#[tokio::test]
async fn file_routes_reject_path_escape_before_runtime_provider() {
    let request = authorized(
        Request::builder().uri(format!("/v1/workspaces/{ID}/files/content?path=../secret")),
    )
    .body(Body::empty())
    .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn file_routes_require_authentication() {
    let request = Request::builder()
        .uri(format!("/v1/workspaces/{ID}/files"))
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
