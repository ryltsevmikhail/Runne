//! A router without ReplayService must not publish a preview or legacy replay surface.

use axum::body::Body;
use http::{Request, StatusCode};
use runne_api::{
    ApiActor, CompleteTaskRunCommand, CreateTaskRunCommand, ExistingTaskRunCommand,
    TaskRunCommandAck, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort, TaskRunSnapshot,
};
use runne_domain::id::TaskRunId;
use runne_http::admission::AdmissionState;
use runne_http::health::{HealthState, RecoveryState};
use runne_http::router::create_router;
use runne_http::task_runs::TaskRunHttpState;
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
        TaskRunHttpState::new(UnavailableHost, ApiActor::new("runne-http-test").unwrap()),
    )
}

#[tokio::test]
async fn taskrun_only_router_does_not_publish_preview_or_canonical_replay_stubs() {
    for uri in [
        "/replay/open-session",
        "/replay/sess-001/read-page",
        "/v1/replay/open-session",
        "/v1/replay/sess-001/read-page",
        "/v1/replay/sess-001/complete-catch-up",
        "/v1/replay/sess-001/continue-live",
        "/v1/replay/sess-001/close",
    ] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}
