use axum::body::{Body, to_bytes};
use gocode_api::{
    ApiActor, BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand,
    ExistingProjectCommand, ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext,
    ProjectPage, ProjectPageRequest, ProjectQueryContext, ProjectSnapshot,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceHostError, ProjectWorkspaceQueryHostPort,
    WorkspaceCommandAck, WorkspacePage, WorkspacePageRequest, WorkspaceSnapshot,
};
use gocode_domain::id::{ProjectId, WorkspaceId};
use gocode_http::{
    admission::AdmissionState,
    health::{HealthState, RecoveryState},
    project_workspace::ProjectWorkspaceHttpState,
    router::create_router_with_project_workspace,
};
use http::{Request, StatusCode};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xA5; 32];
const ID: &str = "0198d1a5-0000-7000-8000-000000000001";

#[derive(Clone)]
struct UnavailableHost;

impl ProjectWorkspaceCommandHostPort for UnavailableHost {
    async fn create_project(
        &self,
        _: ProjectCommandContext,
        _: CreateProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn archive_project(
        &self,
        _: ProjectCommandContext,
        _: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn restore_project(
        &self,
        _: ProjectCommandContext,
        _: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn delete_project(
        &self,
        _: ProjectCommandContext,
        _: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn create_workspace(
        &self,
        _: ProjectCommandContext,
        _: CreateWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn open_workspace(
        &self,
        _: ProjectCommandContext,
        _: ExistingWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn bind_workspace_root(
        &self,
        _: ProjectCommandContext,
        _: BindWorkspaceRootCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
}

impl ProjectWorkspaceQueryHostPort for UnavailableHost {
    async fn list_projects(
        &self,
        _: ProjectQueryContext,
        _: ProjectPageRequest,
    ) -> Result<ProjectPage, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn get_project(
        &self,
        _: ProjectQueryContext,
        _: ProjectId,
    ) -> Result<ProjectSnapshot, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn list_workspaces(
        &self,
        _: ProjectQueryContext,
        _: ProjectId,
        _: WorkspacePageRequest,
    ) -> Result<WorkspacePage, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
    async fn get_workspace(
        &self,
        _: ProjectQueryContext,
        _: WorkspaceId,
    ) -> Result<WorkspaceSnapshot, ProjectWorkspaceHostError> {
        Err(ProjectWorkspaceHostError::Unavailable)
    }
}

fn app() -> axum::Router {
    create_router_with_project_workspace(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        ProjectWorkspaceHttpState::new(UnavailableHost, ApiActor::new("gocode-http-test").unwrap()),
    )
}

fn authorized(request: http::request::Builder) -> http::request::Builder {
    request.header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
}

#[tokio::test]
async fn project_workspace_routes_reject_invalid_pages_and_unknown_bodies() {
    let response = authorized(Request::builder().uri("/v1/projects?limit=0"))
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().contains_key("x-request-id"));

    let response = authorized(Request::builder().method("POST").uri("/v1/projects"))
        .header("x-command-id", ID)
        .header("idempotency-key", "key")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"projectId":"{ID}","displayName":"name","extra":"root-admission-secret"}}"#
        )))
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("root-admission-secret"));
}

#[tokio::test]
async fn root_bind_rejects_non_ascii_opaque_tokens_without_echoing_them() {
    let response = authorized(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/workspaces/{ID}/root-bindings")),
    )
    .header("x-command-id", ID)
    .header("idempotency-key", "key")
    .header("content-type", "application/json")
    .body(Body::from(r#"{"expectedVersion":1,"rootAdmission":"🔒"}"#))
    .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains('🔒'));
}
