//! Production-router checks for removal of synthetic command/query success.

use axum::body::Body;
use gocode_api::{
    ApiActor, CompleteTaskRunCommand, CreateTaskRunCommand, ExistingTaskRunCommand,
    TaskRunCommandAck, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort, TaskRunSnapshot,
};
use gocode_domain::id::TaskRunId;
use gocode_http::admission::AdmissionState;
use gocode_http::health::{HealthState, RecoveryState};
use gocode_http::router::create_router;
use gocode_http::task_runs::TaskRunHttpState;
use http::{Request, StatusCode};
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xAB; 32];

#[derive(Clone)]
struct UnavailableHost;

impl TaskRunCommandHostPort for UnavailableHost {
    async fn create_task_run(
        &self,
        _: TaskRunCommandContext,
        _: CreateTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn queue_task_run(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn admit_task_run(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn start_attempt(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }

    async fn complete_task_run(
        &self,
        _: TaskRunCommandContext,
        _: CompleteTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}

impl TaskRunQueryHostPort for UnavailableHost {
    async fn get_task_run(&self, _: TaskRunId) -> Result<TaskRunSnapshot, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}

fn app() -> axum::Router {
    create_router(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        TaskRunHttpState::new(UnavailableHost, ApiActor::new("gocode-http-test").unwrap()),
    )
}

#[tokio::test]
async fn production_router_does_not_publish_legacy_command_or_query_stubs() {
    for (method, uri) in [
        ("POST", "/commands/create-session"),
        ("POST", "/commands/prompt"),
        ("POST", "/commands/abort"),
        ("POST", "/commands/create-task-run"),
        ("POST", "/commands/complete-task-run"),
        ("GET", "/queries/session/sess-001"),
        ("GET", "/queries/task-run/tr-001"),
    ] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {uri}");
    }
}

#[tokio::test]
async fn production_router_keeps_health_public() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
