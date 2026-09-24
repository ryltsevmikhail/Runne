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

#[tokio::test]
async fn submit_maps_to_one_atomic_host_command_and_validates_the_body() {
    let host = RecordingHost::default();
    let app = app(host.clone());

    let response = app
        .clone()
        .oneshot(command_request(
            "/v2/task-runs/submit",
            7,
            "submit-1",
            format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"add tests"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json(response).await;
    assert_eq!(body["taskRunId"], TASKRUN_ID);
    assert_eq!(body["streamVersion"], 2);
    assert_eq!(body["transition"], "submitted");
    assert_eq!(body["attemptId"], Value::Null);
    assert_eq!(body["terminalResult"], Value::Null);

    let calls = host.calls();
    let [Call::Submit(context, command)] = calls.as_slice() else {
        panic!("submit must reach the host as exactly one atomic command, got {calls:?}");
    };
    assert_eq!(command.conversation_id, CONVERSATION_ID.parse().unwrap());
    assert_eq!(command.workspace_id, WORKSPACE_ID.parse().unwrap());
    assert_eq!(command.input.prompt(), "add tests");
    assert_eq!(context.idempotency_key.as_str(), "submit-1");

    for (body, code) in [
        (
            format!(
                r#"{{"conversationId":"not-a-uuid","workspaceId":"{WORKSPACE_ID}","prompt":"x"}}"#
            ),
            "invalid_conversation_id",
        ),
        (
            r#"{"conversationId":"018f2e3a-7000-7000-8000-000000000042","prompt":"x"}"#.to_owned(),
            "invalid_request",
        ),
        (
            format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}"}}"#),
            "invalid_request",
        ),
        (
            format!(
                r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"x","extra":1}}"#
            ),
            "invalid_request",
        ),
        (
            format!(
                r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":""}}"#
            ),
            "invalid_task_run_input",
        ),
        (
            format!(
                r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"{}"}}"#,
                "x".repeat(runne_domain::task_run::MAX_TASK_RUN_PROMPT_BYTES + 1)
            ),
            "invalid_task_run_input",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(command_request(
                "/v2/task-runs/submit",
                8,
                "submit-invalid",
                body,
            ))
            .await
            .unwrap();
        assert_error(response, StatusCode::BAD_REQUEST, code).await;
    }

    assert_eq!(
        host.calls().len(),
        1,
        "rejected bodies must not reach the host"
    );
}

#[tokio::test]
async fn v1_submit_keeps_the_ids_only_body_and_v2_owns_prompt_input() {
    let host = RecordingHost::default();
    let app = app(host.clone());
    let response = app.clone().oneshot(command_request(
        "/v1/task-runs/submit", 31, "submit-v1",
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}"}}"#),
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(json(response).await["transition"], "submitted");
    assert!(matches!(host.calls().as_slice(), [Call::LegacySubmit(_, command)]
        if command.conversation_id == CONVERSATION_ID.parse().unwrap()
            && command.workspace_id == WORKSPACE_ID.parse().unwrap()));

    let response = app.oneshot(command_request(
        "/v1/task-runs/submit", 32, "submit-v1-invalid",
        format!(r#"{{"conversationId":"{CONVERSATION_ID}","workspaceId":"{WORKSPACE_ID}","prompt":"hello"}}"#),
    )).await.unwrap();
    assert_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    assert_eq!(host.calls().len(), 1);
}
