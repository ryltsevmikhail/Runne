#[tokio::test]
async fn effects_route_exposes_duplicate_execution_warning_for_client_decoding() {
    let host = RecordingHost::default();
    let response = app(host)
        .oneshot(query_request(&format!(
            "/v1/task-runs/{TASKRUN_ID}/effects"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(
        body["successor"],
        "requires_duplicate_effect_acknowledgment"
    );
    assert_eq!(body["remote"]["outcome"], "unknown");
    assert_eq!(body["cancellationRequested"], false);
    assert!(body.get("responseId").is_none());
    assert!(body.get("outputText").is_none());
}

#[tokio::test]
async fn submit_accepts_only_a_complete_structured_local_command() {
    let host = RecordingHost::default();
    let response = app(host.clone()).oneshot(command_request(
        "/v2/task-runs/submit", 31, "typed-local",
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"description, not shell","localCommand":{{"executable":{{"kind":"workspace_relative","value":"bin/tool"}},"cwd":".","argv":["tool","--check"],"env":[{{"key":"A","value":"1"}}]}}}}"#),
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let calls = host.calls();
    let [Call::Submit(_, submitted)] = calls.as_slice() else {
        panic!("typed local command should submit once")
    };
    let command = submitted
        .input
        .local_command()
        .expect("structured command retained");
    assert_eq!(command.executable().value(), "bin/tool");
    assert_eq!(command.cwd(), ".");
    assert_eq!(command.argv(), &["tool", "--check"]);
    assert_eq!(command.env(), &[("A".into(), "1".into())]);
    assert_eq!(submitted.input.prompt(), "description, not shell");
}

#[tokio::test]
async fn submit_rejects_mixed_selection_and_unknown_local_wire_fields() {
    let host = RecordingHost::default();
    let app = app(host.clone());
    let mixed = app.clone().oneshot(command_request(
        "/v2/task-runs/submit", 32, "mixed-local",
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"description","model":"provider/model","localCommand":{{"executable":{{"kind":"workspace_relative","value":"tool"}},"cwd":".","argv":["tool"],"env":[]}}}}"#),
    )).await.unwrap();
    assert_ne!(mixed.status(), StatusCode::ACCEPTED);

    let unknown_origin = app.clone().oneshot(command_request(
        "/v2/task-runs/submit", 33, "unknown-origin-field",
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"description","localCommand":{{"executable":{{"kind":"workspace_relative","value":"tool","extra":true}},"cwd":".","argv":["tool"],"env":[]}}}}"#),
    )).await.unwrap();
    assert_eq!(unknown_origin.status(), StatusCode::BAD_REQUEST);

    let unknown_command = app.oneshot(command_request(
        "/v2/task-runs/submit", 34, "unknown-command-field",
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"description","localCommand":{{"executable":{{"kind":"workspace_relative","value":"tool"}},"cwd":".","argv":["tool"],"env":[],"shell":"tool"}}}}"#),
    )).await.unwrap();
    assert_eq!(unknown_command.status(), StatusCode::BAD_REQUEST);
    assert!(
        host.calls().is_empty(),
        "invalid or mixed requests never reach the host"
    );
}
