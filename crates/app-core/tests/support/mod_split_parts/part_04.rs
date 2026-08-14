async fn reconcile_command(
    State(state): State<Arc<MockState>>,
    axum::Json(witness): axum::Json<Value>,
) -> Response<Body> {
    let outcome = match witness["operation"].as_str() {
        Some("create_conversation") => create_conversation_outcome(&state, &witness),
        Some("generate_conversation_text") => generation_outcome(&state, &witness),
        _ => None,
    };
    let Some(outcome) = outcome else {
        return reconciliation_response(StatusCode::CONFLICT, &json!({
            "code": "command_conflict",
            "requestId": "018f2e3a-7000-7000-8000-000000000199"
        }));
    };
    reconciliation_response(
        StatusCode::OK,
        &json!({"disposition": "durably_recorded", "outcome": outcome}),
    )
}

fn create_conversation_outcome(state: &MockState, witness: &Value) -> Option<Value> {
    let inner = state.inner.lock().ok()?;
    let conversation_id = witness["conversationId"].as_str()?;
    let workspace_id = witness["workspaceId"].as_str()?;
    (inner.conversation_id.as_deref() == Some(conversation_id)
        && inner.workspace_id.as_deref() == Some(workspace_id))
        .then(|| {
            json!({
                "operation": "create_conversation",
                "conversationId": conversation_id,
                "workspaceId": workspace_id,
                "streamVersion": 1,
                "committedAt": 1
            })
        })
}

fn generation_outcome(state: &MockState, witness: &Value) -> Option<Value> {
    let inner = state.inner.lock().ok()?;
    let conversation_id = witness["conversationId"].as_str()?;
    let expected_version = witness["expectedVersion"].as_u64()?;
    let text = witness["text"].as_str()?;
    let assistant = inner.events.last()?.clone();
    let user = inner.events.get(inner.events.len().checked_sub(2)?)?.clone();
    drop(inner);
    let user_payload = user.get("payload")?;
    let assistant_payload = assistant.get("payload")?;
    (assistant["aggregateId"].as_str() == Some(conversation_id)
        && user_payload["text"].as_str() == Some(text)
        && user["sequence"].as_u64()? == expected_version.checked_add(1)?
        && assistant["sequence"].as_u64()? == expected_version.checked_add(2)?)
        .then(|| {
            json!({
                "operation": "generate_conversation_text",
                "terminal": "completed",
                "conversationId": conversation_id,
                "taskRunId": user_payload["taskRunId"],
                "attemptId": user_payload["attemptId"],
                "conversationStreamVersion": assistant["sequence"],
                "taskRunStreamVersion": 5,
                "userMessage": reconciliation_message(user_payload, 2),
                "assistantMessage": reconciliation_message(assistant_payload, 3)
            })
        })
}

fn reconciliation_message(payload: &Value, committed_at: u64) -> Value {
    json!({
        "messageId": payload["messageId"],
        "role": payload["role"],
        "taskRunId": payload["taskRunId"],
        "attemptId": payload["attemptId"],
        "text": payload["text"],
        "committedAt": committed_at
    })
}

fn reconciliation_response(status: StatusCode, body: &Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(serde_json::to_vec(&body).expect("reconciliation JSON")))
        .expect("reconciliation response")
}

fn protected_capability_digest(capabilities: &[String]) -> String {
    use sha2::Digest;

    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(
        u32::try_from(capabilities.len())
            .expect("capability count")
            .to_be_bytes(),
    );
    for capability in capabilities {
        digest.update(
            u32::try_from(capability.len())
                .expect("capability length")
                .to_be_bytes(),
        );
        digest.update(capability.as_bytes());
    }
    hex::encode(digest.finalize())
}
