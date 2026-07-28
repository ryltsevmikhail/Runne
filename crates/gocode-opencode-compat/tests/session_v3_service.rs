use std::sync::{Arc, Mutex};

use gocode_opencode_compat::{
    CanonicalPrompt, CanonicalPromptResult, CanonicalSessionStatus, OpenCodeSessionV1Service,
    SessionV1Error, SessionV1HostError, SessionV1HostPort,
};

const SESSION_ID: &str = "ses_baseline_1";

#[derive(Clone, Default)]
struct FakeHost {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl FakeHost {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl SessionV1HostPort for FakeHost {
    async fn prompt(
        &self,
        input: CanonicalPrompt,
    ) -> Result<CanonicalPromptResult, SessionV1HostError> {
        self.calls.lock().unwrap().push("prompt");
        Ok(CanonicalPromptResult {
            session_id: input.session_id,
            response: serde_json::json!({
                "info": {
                    "id": "msg_assistant_1",
                    "sessionID": SESSION_ID,
                    "role": "assistant",
                    "time": {"created": 1_785_207_600_000_i64},
                    "parentID": "msg_01",
                    "modelID": "canonical-model",
                    "providerID": "canonical-provider",
                    "mode": "agent",
                    "agent": "build",
                    "path": {"cwd": "/workspace", "root": "/workspace"},
                    "cost": 0,
                    "tokens": {
                        "input": 0,
                        "output": 0,
                        "reasoning": 0,
                        "cache": {"read": 0, "write": 0}
                    }
                },
                "parts": [{
                    "id": "prt_assistant_1",
                    "sessionID": SESSION_ID,
                    "messageID": "msg_assistant_1",
                    "type": "text",
                    "text": "Done"
                }]
            }),
        })
    }

    async fn prompt_async(&self, _input: CanonicalPrompt) -> Result<(), SessionV1HostError> {
        self.calls.lock().unwrap().push("prompt_async");
        Ok(())
    }

    async fn status(&self) -> Result<Vec<(String, CanonicalSessionStatus)>, SessionV1HostError> {
        self.calls.lock().unwrap().push("status");
        Ok(vec![
            (SESSION_ID.into(), CanonicalSessionStatus::Busy),
            (
                "ses_baseline_2".into(),
                CanonicalSessionStatus::Retry {
                    attempt: 2,
                    message: "provider rate limited".into(),
                    next: 1_785_207_600_000,
                },
            ),
        ])
    }

    async fn abort(&self, _session_id: String) -> Result<bool, SessionV1HostError> {
        self.calls.lock().unwrap().push("abort");
        Ok(true)
    }
}

fn service(host: FakeHost) -> OpenCodeSessionV1Service<FakeHost> {
    let openapi: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../upstream/opencode/packages/sdk/openapi.json"
    ))
    .unwrap();
    let schema_value = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "allOf": [
            openapi["paths"]["/session/{sessionID}/message"]["post"]["responses"]["200"]
                ["content"]["application/json"]["schema"].clone()
        ],
        "components": openapi["components"].clone()
    });
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema_value)
        .unwrap();
    OpenCodeSessionV1Service::new(host, Arc::new(schema))
}

#[tokio::test]
async fn prompt_and_prompt_async_share_the_exact_canonical_input() {
    let host = FakeHost::default();
    let service = service(host.clone());
    let input: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../docs/golden/session-prompt-request-v1.json"
    ))
    .unwrap();

    let response = service.prompt(SESSION_ID, input.clone()).await.unwrap();
    assert_eq!(response["info"]["sessionID"], SESSION_ID);
    assert_eq!(response["parts"][0]["text"], "Done");
    service.prompt_async(SESSION_ID, input).await.unwrap();
    assert_eq!(host.calls(), vec!["prompt", "prompt_async"]);
}

#[tokio::test]
async fn unsupported_prompt_field_is_rejected_before_host_dispatch() {
    let host = FakeHost::default();
    let service = service(host.clone());
    let input = serde_json::json!({
        "model": {"providerID": "p", "modelID": "m"},
        "parts": [{"type": "text", "text": "hello"}]
    });

    let error = service.prompt(SESSION_ID, input).await.unwrap_err();
    assert!(matches!(
        error,
        SessionV1Error::UnsupportedField { field: "model" }
    ));
    assert!(host.calls().is_empty());
}

#[tokio::test]
async fn unknown_part_type_is_rejected_before_host_dispatch() {
    let host = FakeHost::default();
    let service = service(host.clone());
    let input = serde_json::json!({"parts": [{"type": "file", "url": "file:///secret"}]});

    let error = service.prompt_async(SESSION_ID, input).await.unwrap_err();
    assert!(matches!(
        error,
        SessionV1Error::UnsupportedPart { index: 0 }
    ));
    assert!(host.calls().is_empty());
}

#[tokio::test]
async fn oversized_prompt_is_rejected_before_host_dispatch() {
    let host = FakeHost::default();
    let service = service(host.clone());
    let input = serde_json::json!({
        "parts": [{"type": "text", "text": "x".repeat(1024 * 1024 + 1)}]
    });
    assert!(matches!(
        service.prompt(SESSION_ID, input).await.unwrap_err(),
        SessionV1Error::InvalidRequest { .. }
    ));
    assert!(host.calls().is_empty());
}

#[tokio::test]
async fn status_response_matches_the_pinned_golden_bytes() {
    let service = service(FakeHost::default());
    let actual = serde_jcs::to_vec(&service.status().await.unwrap()).unwrap();
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../docs/golden/session-status-response-v1.json"
    ))
    .unwrap();
    let expected = serde_jcs::to_vec(&fixture).unwrap();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn abort_returns_the_host_boolean_without_fabricating_success() {
    let host = FakeHost::default();
    let service = service(host.clone());
    assert!(service.abort(SESSION_ID).await.unwrap());
    assert_eq!(host.calls(), vec!["abort"]);
}
