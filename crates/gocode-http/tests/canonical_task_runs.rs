use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use gocode_api::{
    ApiActor, CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand,
    CreateTaskRunCommand, ExistingTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind,
    TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort,
    TaskRunSnapshot,
};
use gocode_domain::id::{AttemptId, TaskRunId};
use gocode_http::admission::AdmissionState;
use gocode_http::health::{HealthState, RecoveryState};
use gocode_http::router::create_router;
use gocode_http::task_runs::TaskRunHttpState;
use http::{Request, Response, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xAB; 32];
const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000040";
const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000041";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000042";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000043";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Create(TaskRunCommandContext, CreateTaskRunCommand),
    Queue(TaskRunCommandContext, ExistingTaskRunCommand),
    Admit(TaskRunCommandContext, ExistingTaskRunCommand),
    Start(TaskRunCommandContext, ExistingTaskRunCommand),
    Complete(TaskRunCommandContext, CompleteTaskRunCommand),
    Get(TaskRunId),
}

#[derive(Clone, Default)]
struct RecordingHost {
    calls: Arc<Mutex<Vec<Call>>>,
    next_error: Arc<Mutex<Option<TaskRunHostError>>>,
}

impl RecordingHost {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn fail_next(&self, error: TaskRunHostError) {
        *self.next_error.lock().unwrap() = Some(error);
    }

    fn record(&self, call: Call) -> Result<(), TaskRunHostError> {
        self.calls.lock().unwrap().push(call);
        match self.next_error.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl TaskRunCommandHostPort for RecordingHost {
    async fn create_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CreateTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Create(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: TASKRUN_ID.parse().unwrap(),
            new_version: 1,
            kind: TaskRunCommandAckKind::Created,
        })
    }

    async fn queue_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Queue(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::Queued,
        })
    }

    async fn admit_task_run(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Admit(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::Admitted,
        })
    }

    async fn start_attempt(
        &self,
        context: TaskRunCommandContext,
        command: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Start(context, command))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::AttemptStarted {
                attempt_id: ATTEMPT_ID.parse::<AttemptId>().unwrap(),
            },
        })
    }

    async fn complete_task_run(
        &self,
        context: TaskRunCommandContext,
        command: CompleteTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        self.record(Call::Complete(context, command.clone()))?;
        Ok(TaskRunCommandAck {
            taskrun_id: command.taskrun_id,
            new_version: command.expected_version + 1,
            kind: TaskRunCommandAckKind::Completed {
                result: command.result,
            },
        })
    }
}

impl TaskRunQueryHostPort for RecordingHost {
    async fn get_task_run(
        &self,
        taskrun_id: TaskRunId,
    ) -> Result<TaskRunSnapshot, TaskRunHostError> {
        self.record(Call::Get(taskrun_id))?;
        Ok(TaskRunSnapshot {
            taskrun_id,
            state: CanonicalTaskRunState::Running,
            stream_version: 4,
            active_attempt_id: Some(ATTEMPT_ID.parse().unwrap()),
            terminal_result: None,
        })
    }
}

fn app(host: RecordingHost) -> axum::Router {
    create_router(
        TOKEN,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        TaskRunHttpState::new(host, ApiActor::new("gocode-http-test").unwrap()),
    )
}

fn command_request(uri: &str, sequence: u8, key: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .header(
            "x-command-id",
            format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}"),
        )
        .header("idempotency-key", key)
        .body(body.into())
        .unwrap()
}

fn query_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .body(Body::empty())
        .unwrap()
}

async fn json(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn assert_error(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let request_id = response
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = json(response).await;
    assert_eq!(body["code"], code);
    assert_eq!(body["requestId"], request_id);
}

#[tokio::test]
async fn maps_every_canonical_route_to_the_exact_host_command() {
    let host = RecordingHost::default();
    let app = app(host.clone());

    let response = app
        .clone()
        .oneshot(command_request(
            "/v1/task-runs",
            1,
            "create-1",
            format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json(response).await;
    assert_eq!(body["taskRunId"], TASKRUN_ID);
    assert_eq!(body["streamVersion"], 1);
    assert_eq!(body["transition"], "created");

    for (sequence, route, expected_version, expected_transition) in [
        (2, "queue", 1, "queued"),
        (3, "admit", 2, "admitted"),
        (4, "attempts", 3, "attempt_started"),
    ] {
        let response = app
            .clone()
            .oneshot(command_request(
                &format!("/v1/task-runs/{TASKRUN_ID}/{route}"),
                sequence,
                &format!("{route}-1"),
                format!(r#"{{"expectedVersion":{expected_version}}}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = json(response).await;
        assert_eq!(body["transition"], expected_transition);
        assert_eq!(body["streamVersion"], expected_version + 1);
    }

    let response = app
        .clone()
        .oneshot(command_request(
            &format!("/v1/task-runs/{TASKRUN_ID}/complete"),
            5,
            "complete-1",
            r#"{"expectedVersion":4,"result":{"type":"failure","reason":"provider failed"}}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json(response).await;
    assert_eq!(body["transition"], "completed");
    assert_eq!(body["terminalResult"]["type"], "failure");
    assert_eq!(body["terminalResult"]["reason"], "provider failed");

    let response = app
        .oneshot(query_request(&format!("/v1/task-runs/{TASKRUN_ID}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["state"], "running");
    assert_eq!(body["streamVersion"], 4);
    assert_eq!(body["activeAttemptId"], ATTEMPT_ID);

    let calls = host.calls();
    assert_eq!(calls.len(), 6);
    let Call::Create(context, command) = &calls[0] else {
        panic!("first call was not create");
    };
    assert_eq!(
        context.command_id.to_string(),
        "018f2e3a-7000-7000-8000-000000000001"
    );
    assert_eq!(context.idempotency_key.as_str(), "create-1");
    assert_eq!(context.principal.as_str(), "local-owner");
    assert_eq!(context.actor.as_str(), "gocode-http-test");
    assert_eq!(command.conversation_id.to_string(), CONVERSATION_ID);
    assert_eq!(command.workspace_id.to_string(), WORKSPACE_ID);

    let Call::Complete(_, command) = &calls[4] else {
        panic!("fifth call was not completion");
    };
    assert_eq!(command.taskrun_id.to_string(), TASKRUN_ID);
    assert_eq!(command.expected_version, 4);
    assert_eq!(
        command.result,
        CanonicalTerminalResult::Failure {
            reason: "provider failed".to_owned(),
        }
    );
    assert_eq!(calls[5], Call::Get(TASKRUN_ID.parse().unwrap()));
}

#[tokio::test]
async fn rejects_auth_headers_paths_and_bodies_before_host_dispatch() {
    let host = RecordingHost::default();
    let app = app(host.clone());
    let valid_body =
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}"}}"#);

    let missing_auth = Request::builder()
        .method("POST")
        .uri("/v1/task-runs")
        .header("content-type", "application/json")
        .header("x-command-id", "018f2e3a-7000-7000-8000-000000000010")
        .header("idempotency-key", "missing-auth")
        .body(Body::from(valid_body.clone()))
        .unwrap();
    assert_error(
        app.clone().oneshot(missing_auth).await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;

    let wrong_auth = Request::builder()
        .method("GET")
        .uri(format!("/v1/task-runs/{TASKRUN_ID}"))
        .header(
            "authorization",
            format!("Bearer {}", hex::encode([0xCD; 32])),
        )
        .body(Body::empty())
        .unwrap();
    assert_error(
        app.clone().oneshot(wrong_auth).await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;

    let invalid_command_id = Request::builder()
        .method("POST")
        .uri("/v1/task-runs")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .header("x-command-id", "not-a-uuid")
        .header("idempotency-key", "invalid-command")
        .body(Body::from(valid_body.clone()))
        .unwrap();
    assert_error(
        app.clone().oneshot(invalid_command_id).await.unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_command_id",
    )
    .await;

    assert_error(
        app.clone()
            .oneshot(command_request(
                "/v1/task-runs",
                11,
                "unknown-field",
                format!(
                    r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","extra":true}}"#
                ),
            ))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;

    assert_error(
        app.clone()
            .oneshot(command_request(
                "/v1/task-runs/not-a-uuid/queue",
                12,
                "invalid-path",
                r#"{"expectedVersion":1}"#,
            ))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_task_run_id",
    )
    .await;

    assert_error(
        app.clone()
            .oneshot(command_request("/v1/task-runs", 13, "malformed-json", "{"))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;

    let long_reason = "x".repeat(4097);
    assert_error(
        app.clone()
            .oneshot(command_request(
                &format!("/v1/task-runs/{TASKRUN_ID}/complete"),
                14,
                "long-reason",
                format!(
                    r#"{{"expectedVersion":4,"result":{{"type":"failure","reason":"{long_reason}"}}}}"#
                ),
            ))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_terminal_reason",
    )
    .await;

    let oversized_reason = "x".repeat(20 * 1024);
    assert_error(
        app.clone()
            .oneshot(command_request(
                &format!("/v1/task-runs/{TASKRUN_ID}/complete"),
                15,
                "oversized-body",
                format!(
                    r#"{{"expectedVersion":4,"result":{{"type":"failure","reason":"{oversized_reason}"}}}}"#
                ),
            ))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;

    assert!(host.calls().is_empty());
}

#[tokio::test]
async fn maps_closed_host_errors_to_stable_redacted_http_errors() {
    let host = RecordingHost::default();
    let app = app(host.clone());

    for (sequence, error, status, code) in [
        (
            21,
            TaskRunHostError::Conflict,
            StatusCode::CONFLICT,
            "task_run_conflict",
        ),
        (
            22,
            TaskRunHostError::Backpressure,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_backpressure",
        ),
        (
            23,
            TaskRunHostError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
        ),
        (
            24,
            TaskRunHostError::InvariantViolation,
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    ] {
        host.fail_next(error);
        let response = app
            .clone()
            .oneshot(command_request(
                &format!("/v1/task-runs/{TASKRUN_ID}/queue"),
                sequence,
                &format!("error-{sequence}"),
                r#"{"expectedVersion":1}"#,
            ))
            .await
            .unwrap();
        assert_error(response, status, code).await;
    }

    host.fail_next(TaskRunHostError::NotFound);
    let response = app
        .oneshot(query_request(&format!("/v1/task-runs/{TASKRUN_ID}")))
        .await
        .unwrap();
    assert_error(response, StatusCode::NOT_FOUND, "task_run_not_found").await;
}
