use axum::body::{Body, to_bytes};
use http::{Request, StatusCode};
use runne_api::{
    ApiActor, BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand,
    ExistingProjectCommand, ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext,
    ProjectPage, ProjectPageRequest, ProjectQueryContext, ProjectSnapshot,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceHostError, ProjectWorkspaceQueryHostPort,
    RenameProjectCommand, WorkspaceCommandAck, WorkspacePage, WorkspacePageRequest,
    WorkspaceSnapshot,
};
use runne_domain::id::{ProjectId, WorkspaceId};
use runne_http::{
    admission::AdmissionState,
    health::{HealthState, RecoveryState},
    project_workspace::ProjectWorkspaceHttpState,
    router::create_router_with_project_workspace,
};
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
    async fn rename_project(
        &self,
        _: ProjectCommandContext,
        _: RenameProjectCommand,
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
        ProjectWorkspaceHttpState::new(UnavailableHost, ApiActor::new("runne-http-test").unwrap()),
    )
}

fn authorized(request: http::request::Builder) -> http::request::Builder {
    request.header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
}

#[path = "project_workspace/rename.rs"]
mod rename;

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

#[tokio::test]
async fn root_bind_rejects_oversized_admission_before_the_host() {
    let response = authorized(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/workspaces/{ID}/root-bindings")),
    )
    .header("x-command-id", ID)
    .header("idempotency-key", "key")
    .header("content-type", "application/json")
    .body(Body::from(format!(
        r#"{{"expectedVersion":1,"rootAdmission":"{}"}}"#,
        "a".repeat(runne_api::MAX_ROOT_HANDLE_ADMISSION_TOKEN_BYTES + 1),
    )))
    .unwrap();
    assert_eq!(
        app().oneshot(response).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn root_bind_is_present_but_fail_closed_without_a_native_admission_producer() {
    let response = authorized(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/workspaces/{ID}/root-bindings")),
    )
    .header("x-command-id", ID)
    .header("idempotency-key", "key")
    .header("content-type", "application/json")
    .body(Body::from(format!(
        r#"{{"expectedVersion":1,"rootAdmission":"gocode-root-admission-v3.{}"}}"#,
        "A".repeat((runne_api::ROOT_HANDLE_ADMISSION_V3_BYTES * 4).div_ceil(3)),
    )))
    .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains(r#""code":"runtime_unavailable""#));
    assert!(!body.contains("nonce"));
    assert!(!body.contains("state"));
}

#[tokio::test]
async fn project_workspace_router_canonicalizes_wrong_method_and_body_limit() {
    let response = authorized(Request::builder().method("PUT").uri("/v1/projects"))
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let header = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["requestId"],
        header
    );

    for (size, status) in [
        (16 * 1024, StatusCode::BAD_REQUEST),
        (16 * 1024 + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let json = format!(r#"{{"extra":"{}"}}"#, "x".repeat(size - 12));
        assert_eq!(json.len(), size);
        let response = authorized(Request::builder().method("POST").uri("/v1/projects"))
            .header("x-command-id", ID)
            .header("idempotency-key", "body-limit")
            .header("content-type", "application/json")
            .header("content-length", size)
            .body(Body::from(json))
            .unwrap();
        let response = app().oneshot(response).await.unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            assert_canonical_payload_too_large(response).await;
        }
    }

    let json = format!(r#"{{"extra":"{}"}}"#, "x".repeat(16 * 1024 + 1 - 12));
    let chunks = json
        .as_bytes()
        .chunks(1024)
        .map(|chunk| Ok::<_, std::convert::Infallible>(bytes::Bytes::copy_from_slice(chunk)))
        .collect::<Vec<_>>();
    let response = authorized(Request::builder().method("POST").uri("/v1/projects"))
        .header("x-command-id", ID)
        .header("idempotency-key", "body-limit-stream")
        .header("content-type", "application/json")
        .body(Body::from_stream(futures::stream::iter(chunks)))
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_canonical_payload_too_large(response).await;

    let response = authorized(Request::builder().uri("/v1/projects"))
        .header("content-length", 16 * 1024 + 1)
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_canonical_payload_too_large(response).await;
}

async fn assert_canonical_payload_too_large(response: axum::response::Response) {
    let header = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["code"], "payload_too_large");
    assert_eq!(body["requestId"], header);
}
