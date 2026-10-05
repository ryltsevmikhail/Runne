mod managed_api_tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Method, Request, Response, StatusCode},
        routing::any,
    };
    use serde_json::{Value, json};
    use sha2::Digest;
    use std::collections::HashMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000903";
    const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000902";
    const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000901";
    const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000904";
    const TASK_RUN_NEXT: &str = "018f2e3a-7000-7000-8000-000000000915";
    const APPROVAL: &str = "018f2e3a-7000-7000-8000-000000000905";
    const INVOCATION: &str = "018f2e3a-7000-7000-8000-000000000906";
    const ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000907";

    #[derive(Clone)]
    struct ManagedApiMock {
        submissions: Arc<AtomicUsize>,
        task_run_ids: Arc<Mutex<HashMap<String, &'static str>>>,
        fail_approvals: bool,
        task_runs: Value,
        approvals: Value,
    }

    async fn managed_api_server(mock: ManagedApiMock) -> String {
        let router = Router::new()
            .fallback(any(managed_api_request))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{address}")
    }

    async fn managed_api_request(
        State(mock): State<ManagedApiMock>,
        request: Request<Body>,
    ) -> Response<Body> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let command_key = request
            .headers()
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(request.into_body(), 128 * 1024)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let response = match (method, path.as_str()) {
            (Method::GET, p) if p.starts_with("/v1/workspaces/") => json!({
                "workspaceId": WORKSPACE, "projectId": PROJECT, "displayName": "Workspace",
                "version": 1, "open": true
            }),
            (Method::POST, "/v1/conversations") => json!({
                "conversationId": body["conversationId"], "workspaceId": body["workspaceId"],
                "streamVersion": 1, "committedAt": 1
            }),
            (Method::POST, "/v1/replay/open-session") => {
                let conversation_id = body["aggregateId"].as_str().unwrap_or(CONVERSATION);
                let events = if body["fromCursor"].is_null() {
                    vec![json!({
                        "aggregateId":conversation_id, "aggregateType":"conversation",
                        "causationEventId":"018f2e3a-7000-7000-8000-000000000909",
                        "correlationId":conversation_id, "correlationType":"conversation",
                        "cursor":"gocode-replay-cursor-v1.7b7d",
                        "eventId":"018f2e3a-7000-7000-8000-000000000909",
                        "eventType":"conversation.created",
                        "integrityDigest":"1111111111111111111111111111111111111111111111111111111111111111",
                        "payload":{"type":"conversation.created","workspaceId":WORKSPACE},
                        "replayBindingId":"018f2e3a700070008000000000000121",
                        "schemaVersion":1, "sensitivity":"sensitive", "sequence":1,
                        "timestampUnixMicros":1_722_330_000_000_000_i64
                    })]
                } else {
                    Vec::new()
                };
                json!({"sessionId":"018f2e3a700070008000000000000118",
                "highWaterRef":"aa", "events":events, "hasMore":false})
            }
            (Method::POST, p) if p.ends_with("/acknowledge") => json!({"acknowledged":true}),
            (Method::POST, p) if p.ends_with("/complete-catch-up") => json!({
                "catchUpProof": "bb", "sessionState": "catch_up_complete"
            }),
            (Method::POST, p) if p.ends_with("/continue-live") => json!({
                "liveDeliveryId": "018f2e3a-7000-7000-8000-000000000908", "sessionState": "live"
            }),
            (Method::POST, "/v2/task-runs/submit") => {
                let count = mock.submissions.fetch_add(1, Ordering::SeqCst);
                let task_run_id = if count == 0 { TASK_RUN } else { TASK_RUN_NEXT };
                if let Some(key) = command_key.as_ref() {
                    mock.task_run_ids
                        .lock()
                        .unwrap()
                        .insert(key.clone(), task_run_id);
                }
                json!({"taskRunId": task_run_id, "streamVersion": 2, "transition": "submitted",
                "attemptId": null, "terminalResult": null})
            }
            (Method::POST, "/v1/commands/reconcile") => {
                let outcome = match body["operation"].as_str().unwrap_or("") {
                    "create_conversation" => json!({"operation":"create_conversation",
                    "conversationId": body["conversationId"],
                    "workspaceId": body["workspaceId"], "streamVersion":1, "committedAt":1}),
                    "submit_task_run" => {
                        let task_run_id = command_key
                            .as_ref()
                            .and_then(|key| mock.task_run_ids.lock().unwrap().get(key).copied())
                            .unwrap_or(TASK_RUN);
                        json!({"operation":"submit_task_run", "taskRunId":task_run_id, "newVersion":2})
                    }
                    _ => json!({"operation":"unknown"}),
                };
                let response = json!({"disposition":"durably_recorded", "outcome":outcome});
                response
            }
            (Method::GET, "/v1/task-runs") => json!({"taskRuns": mock.task_runs}),
            (Method::GET, "/v1/approvals") if mock.fail_approvals => {
                return json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &json!({"code":"runtime_unavailable","requestId":"018f2e3a-7000-7000-8000-000000000910"}),
                );
            }
            (Method::GET, "/v1/approvals") => json!({"items":mock.approvals}),
            _ => return json_response(StatusCode::NOT_FOUND, &json!({"code":"not_found"})),
        };
        let status = if path == "/v2/task-runs/submit" || path == "/v1/conversations" {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        json_response(status, &response)
    }

    fn json_response(status: StatusCode, value: &Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .body(Body::from(value.to_string()))
            .unwrap()
    }

    fn bind_workspace_conversation(core: &AppCore, workspace: &str) -> String {
        let reference = core
            .load_or_prepare_workspace_conversation_reference(workspace)
            .unwrap();
        let runtime =
            crate::replay::StableRuntimeIdentity::from_client(&core.live_runtime_client().unwrap());
        let owner =
            crate::ConversationReferenceOwner::Workspace(CanonicalId::parse(workspace).unwrap());
        core.bind_conversation_reference_for_owner(owner, reference, &runtime)
            .unwrap()
            .conversation_id()
            .to_string()
    }

    fn run_snapshot(id: &str, state: &str, active: Option<&str>, terminal: &Value) -> Value {
        json!({"taskRunId":id, "conversationId":CONVERSATION, "workspaceId":WORKSPACE,
        "state":state, "streamVersion":4, "activeAttemptId":active, "terminalResult":terminal})
    }

    include!("managed_api_start_tests.rs");
    include!("managed_api_attention_tests.rs");

    include!("managed_attention_effects_tests.rs");
    include!("managed_receipt_intent_tests.rs");
}
