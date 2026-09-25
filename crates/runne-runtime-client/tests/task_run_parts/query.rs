use super::support::*;

#[tokio::test]
async fn task_run_query_uses_authenticated_exact_get_and_decodes_running_snapshot() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read");
            assert_ne!(read, 0, "request headers");
            request.extend_from_slice(&buffer[..read]);
        }
        let body = format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"running\",\"streamVersion\":3,\"activeAttemptId\":\"{ATTEMPT_ID}\",\"terminalResult\":null}}"
        );
        stream
            .write_all(response(200, "OK", &body).as_bytes())
            .await
            .expect("response");
        String::from_utf8(request).expect("request UTF-8")
    });
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let task_run_id = CanonicalId::parse(TASK_RUN_ID).expect("task run ID");

    let snapshot = client.get_task_run(task_run_id).await.expect("task run");
    let request = server.await.expect("server");
    assert!(request.starts_with(&format!("GET /v1/task-runs/{TASK_RUN_ID} HTTP/1.1")));
    assert!(request.contains("authorization: GocodeSession "));
    assert_eq!(snapshot.task_run_id(), task_run_id);
    assert_eq!(snapshot.state(), TaskRunState::Running);
    assert_eq!(
        snapshot.active_attempt_id(),
        CanonicalId::parse(ATTEMPT_ID).ok()
    );
}

#[tokio::test]
async fn task_run_snapshot_enforces_terminal_and_active_attempt_invariants() {
    let succeeded = query_snapshot(&format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"succeeded\",\"streamVersion\":4,\"activeAttemptId\":null,\"terminalResult\":{{\"type\":\"failure\",\"reason\":\"settled failure\"}}}}"
    ))
    .await;
    assert_eq!(succeeded.state(), TaskRunState::Succeeded);
    assert_eq!(
        succeeded.terminal_result(),
        Some(&TaskRunTerminalResult::Failure {
            reason: "settled failure".to_owned()
        })
    );

    for state in [
        "running",
        "waiting",
        "retrying",
        "checkpointing",
        "reconciling",
    ] {
        assert!(
            query_snapshot_result(&snapshot_body(state, None))
                .await
                .is_err()
        );
        assert!(
            query_snapshot_result(&snapshot_body(state, Some(ATTEMPT_ID)))
                .await
                .is_ok()
        );
    }
    for state in [
        "created",
        "queued",
        "admitted",
        "failed",
        "cancelled",
        "budget_exhausted",
        "policy_denied",
        "unrecoverable",
    ] {
        assert!(
            query_snapshot_result(&snapshot_body(state, Some(ATTEMPT_ID)))
                .await
                .is_err()
        );
        assert!(
            query_snapshot_result(&snapshot_body(state, None))
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn task_run_snapshot_rejects_malformed_contract_shape() {
    for body in [
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"running\",\"streamVersion\":0,\"activeAttemptId\":\"{ATTEMPT_ID}\",\"terminalResult\":null}}"
        ),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"created\",\"streamVersion\":4,\"terminalResult\":null}}"
        ),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"created\",\"streamVersion\":4,\"activeAttemptId\":null}}"
        ),
        format!(
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"succeeded\",\"streamVersion\":4,\"activeAttemptId\":null,\"terminalResult\":{{\"type\":\"failure\",\"reason\":\"\"}}}}"
        ),
    ] {
        assert!(query_snapshot_result(&body).await.is_err());
    }
}
