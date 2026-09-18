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
    assert_eq!(context.actor.as_str(), "runne-http-test");
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
async fn exposes_an_authenticated_task_run_cancel_command() {
    let host = RecordingHost::default();
    let app = app(host.clone());
    let response = app
        .oneshot(command_request(
            &format!("/v1/task-runs/{TASKRUN_ID}/cancel"),
            6,
            "cancel-1",
            r#"{"expectedVersion":4}"#,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json(response).await;
    assert_eq!(body["transition"], "cancellation_requested");
    assert_eq!(body["streamVersion"], 5);
    let calls = host.calls();
    assert_eq!(calls.len(), 1);
    let Call::Cancel(context, command) = &calls[0] else {
        panic!("cancel route did not reach the cancellation host command");
    };
    assert_eq!(context.idempotency_key.as_str(), "cancel-1");
    assert_eq!(command.taskrun_id.to_string(), TASKRUN_ID);
    assert_eq!(command.expected_version, 4);
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
