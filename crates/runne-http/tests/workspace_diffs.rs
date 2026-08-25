use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use runne_api::{
    WorkspaceChangeListRequest, WorkspaceChangeSet, WorkspaceDiff, WorkspaceDiffHostError,
    WorkspaceDiffHostPort, WorkspaceDiffQueryContext, WorkspaceDiffReadRequest,
};
use runne_http::{
    admission::AdmissionState,
    health::{HealthState, RecoveryState},
    router::create_router_with_workspace_diffs,
    workspace_diffs::WorkspaceDiffHttpState,
};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const ID: &str = "0198d1a5-0000-7000-8000-000000000001";

#[derive(Clone)]
struct Unavailable;

impl WorkspaceDiffHostPort for Unavailable {
    async fn list_changes(
        &self,
        _: WorkspaceDiffQueryContext,
        _: WorkspaceChangeListRequest,
    ) -> Result<WorkspaceChangeSet, WorkspaceDiffHostError> {
        Err(WorkspaceDiffHostError::Unavailable)
    }
    async fn read_diff(
        &self,
        _: WorkspaceDiffQueryContext,
        _: WorkspaceDiffReadRequest,
    ) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
        Err(WorkspaceDiffHostError::Unavailable)
    }
}

fn app() -> axum::Router {
    create_router_with_workspace_diffs(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        WorkspaceDiffHttpState::new(Unavailable),
    )
}

#[tokio::test]
async fn diff_routes_reject_path_escape_before_runtime_provider() {
    let request = Request::builder()
        .uri(format!("/v1/workspaces/{ID}/diff?path=../secret"))
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
