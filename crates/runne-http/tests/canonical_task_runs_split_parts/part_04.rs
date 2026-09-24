#[tokio::test]
async fn submit_accepts_the_maximum_prompt_after_json_unescaping() {
    let host = RecordingHost::default();
    let app = app(host.clone());
    let prompt = "\0".repeat(runne_api::MAX_TASK_RUN_PROMPT_BYTES);
    let prompt_json = serde_json::to_string(&prompt).expect("prompt JSON");
    let body = format!(
        r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":{prompt_json}}}"#
    );
    let response = app
        .oneshot(command_request(
            "/v2/task-runs/submit",
            9,
            "submit-boundary",
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let calls = host.calls();
    let [Call::Submit(_, command)] = calls.as_slice() else {
        panic!("maximum sized prompt must reach the host");
    };
    assert_eq!(
        command.input.prompt().len(),
        runne_api::MAX_TASK_RUN_PROMPT_BYTES
    );
}
