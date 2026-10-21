use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use runne_api::{
    ApiActor, CompleteTaskRunCommand, CreateTaskRunCommand, ExistingTaskRunCommand,
    TaskRunCommandAck, TaskRunCommandContext, TaskRunCommandHostPort, TaskRunHostError,
    TaskRunQueryHostPort, TaskRunSnapshot,
};
use runne_domain::id::TaskRunId;
use runne_http::opencode::{OpenCodeSessionState, opencode_session_router};
use runne_http::{
    admission::AdmissionState,
    health::{HealthState, RecoveryState},
    router::create_router_with_opencode,
    task_runs::TaskRunHttpState,
};
use runne_opencode_compat::{
    CanonicalPrompt, CanonicalPromptResult, CanonicalSessionStatus, OpenCodeSessionV1Service,
    SessionV1HostError, SessionV1HostPort,
};
use tower::ServiceExt;

#[derive(Clone)]
struct Host;

impl TaskRunCommandHostPort for Host {
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

impl TaskRunQueryHostPort for Host {
    async fn get_task_run(&self, _: TaskRunId) -> Result<TaskRunSnapshot, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}

impl SessionV1HostPort for Host {
    async fn prompt(
        &self,
        input: CanonicalPrompt,
    ) -> Result<CanonicalPromptResult, SessionV1HostError> {
        Ok(CanonicalPromptResult {
            session_id: input.session_id.clone(),
            response: serde_json::json!({
                "info": {
                    "id": "msg_assistant_1",
                    "sessionID": input.session_id,
                    "role": "assistant",
                    "time": {"created": 1_785_207_600_000_i64},
                    "parentID": "msg_user_1",
                    "modelID": "canonical-model",
                    "providerID": "canonical-provider",
                    "mode": "agent",
                    "agent": "build",
                    "path": {"cwd": "/workspace", "root": "/workspace"},
                    "cost": 0,
                    "tokens": {
                        "input": 0, "output": 0, "reasoning": 0,
                        "cache": {"read": 0, "write": 0}
                    }
                },
                "parts": [{
                    "id": "prt_assistant_1",
                    "sessionID": input.session_id,
                    "messageID": "msg_assistant_1",
                    "type": "text",
                    "text": input.text_parts.join("")
                }]
            }),
        })
    }

    async fn prompt_async(&self, _: CanonicalPrompt) -> Result<(), SessionV1HostError> {
        Ok(())
    }

    async fn status(&self) -> Result<Vec<(String, CanonicalSessionStatus)>, SessionV1HostError> {
        Ok(vec![("ses_http_1".into(), CanonicalSessionStatus::Busy)])
    }

    async fn abort(&self, _: String) -> Result<bool, SessionV1HostError> {
        Ok(true)
    }
}

fn app() -> axum::Router {
    opencode_session_router(state())
}

fn state() -> OpenCodeSessionState<Host> {
    let openapi: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/compatibility/session-response-openapi.json"
    ))
    .unwrap();
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "allOf": [openapi["paths"]["/session/{sessionID}/message"]["post"]
                ["responses"]["200"]["content"]["application/json"]["schema"].clone()],
            "components": openapi["components"].clone()
        }))
        .unwrap();
    OpenCodeSessionState::new(OpenCodeSessionV1Service::new(Host, Arc::new(schema)))
}

async fn call(method: &str, uri: &str, body: &'static str) -> (StatusCode, Vec<u8>) {
    let response = app()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn all_four_pinned_routes_are_real_http_handlers() {
    let (status, body) = call(
        "POST",
        "/session/ses_http_1/message",
        r#"{"messageID":"msg_user_1","parts":[{"type":"text","text":"done"}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["parts"][0]["text"],
        "done"
    );

    assert_eq!(
        call(
            "POST",
            "/session/ses_http_1/prompt_async",
            r#"{"parts":[{"type":"text","text":"queued"}]}"#,
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(call("GET", "/session/status", "").await.0, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &call("POST", "/session/ses_http_1/abort", "").await.1
        )
        .unwrap(),
        serde_json::json!(true)
    );
}

#[tokio::test]
async fn malformed_and_unsupported_inputs_fail_closed() {
    assert_eq!(
        call("POST", "/session/not-a-session/message", "{}").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            "POST",
            "/session/ses_http_1/message",
            r#"{"model":{"providerID":"x"},"parts":[]}"#
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        call("POST", "/session/ses_http_1/message", "{").await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn parent_router_applies_auth_and_admission_to_compatibility_routes() {
    let app = create_router_with_opencode::<Host, Host>(
        [7; 32],
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        TaskRunHttpState::new(Host, ApiActor::new("runne-http-test").unwrap(), None),
        state(),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/session/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn governed_outcome_fixture_covers_success_error_and_loss_for_every_route() {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../docs/golden/session-v1-route-outcomes-v1.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["baseline_sha"],
        "66495a2a22cd0a57efcc4f721e65532f0987b4e8"
    );
    for route in [
        "session.prompt",
        "session.prompt_async",
        "session.status",
        "session.abort",
    ] {
        for disposition in ["success", "error", "loss"] {
            assert!(
                fixture["routes"][route][disposition]["status"]
                    .as_u64()
                    .is_some(),
                "{route} lacks {disposition}"
            );
        }
    }
}
