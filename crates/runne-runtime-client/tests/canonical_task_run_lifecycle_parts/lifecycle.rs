#[tokio::test]
async fn prompted_submit_get_list_cancel_uses_public_v2_and_v1_read_routes() {
    let queued = support::snapshot_json(TASK_RUN_ID, "queued", 2, None, None);
    let (origin, server) = support::serve(vec![
        support::RawResponse::json(202, "Accepted", ack(TASK_RUN_ID, 2, "submitted")),
        support::RawResponse::json(200, "OK", queued.clone()),
        support::RawResponse::json(200, "OK", support::list_json(&[queued])),
        support::RawResponse::json(
            202,
            "Accepted",
            ack(TASK_RUN_ID, 3, "cancellation_requested"),
        ),
    ])
    .await;
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");

    let submitted = client
        .submit_task_run(
            SubmitTaskRunRequest::new(
                identity(COMMAND_ID, "x2-submit"),
                id(CONVERSATION_ID),
                id(WORKSPACE_ID),
                "fix this issue",
            )
            .expect("valid prompt"),
        )
        .await
        .expect("prompted submit");
    assert_eq!(submitted.task_run_id(), id(TASK_RUN_ID));
    assert_eq!(submitted.stream_version(), 2);

    let snapshot = client.get_task_run(id(TASK_RUN_ID)).await.expect("get");
    assert_eq!(snapshot.state(), TaskRunState::Queued);
    assert_eq!(snapshot.stream_version(), 2);
    let listed = client.list_task_runs().await.expect("list");
    assert_eq!(listed, vec![snapshot]);

    let cancelled = client
        .cancel_task_run(CancelTaskRunRequest::new(
            identity(CANCEL_COMMAND_ID, "x2-cancel"),
            id(TASK_RUN_ID),
            2,
        ))
        .await
        .expect("cancel");
    assert_eq!(cancelled.task_run_id(), id(TASK_RUN_ID));
    assert_eq!(cancelled.stream_version(), 3);

    let requests = server.await.expect("fixture");
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].start_line, "POST /v2/task-runs/submit HTTP/1.1");
    assert_eq!(
        requests[0].body,
        format!(
            "{{\"conversationId\":\"{CONVERSATION_ID}\",\"workspaceId\":\"{WORKSPACE_ID}\",\"prompt\":\"fix this issue\"}}"
        )
    );
    assert_eq!(
        requests[1].start_line,
        format!("GET /v1/task-runs/{TASK_RUN_ID} HTTP/1.1")
    );
    assert_eq!(requests[2].start_line, "GET /v1/task-runs HTTP/1.1");
    assert_eq!(
        requests[3].start_line,
        format!("POST /v1/task-runs/{TASK_RUN_ID}/cancel HTTP/1.1")
    );
    for (index, request) in requests.iter().enumerate() {
        let mutation = index == 0 || index == 3;
        assert_eq!(request.header("x-command-id").is_some(), mutation);
        assert_eq!(request.header("idempotency-key").is_some(), mutation);
    }
}
