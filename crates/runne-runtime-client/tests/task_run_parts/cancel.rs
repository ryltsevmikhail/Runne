use super::support::*;

#[tokio::test]
async fn task_run_cancel_uses_authenticated_command_and_validates_ack() {
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
            "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":5,\"transition\":\"cancellation_requested\",\"attemptId\":null,\"terminalResult\":null}}"
        );
        stream
            .write_all(response(202, "Accepted", &body).as_bytes())
            .await
            .expect("response");
        String::from_utf8(request).expect("request UTF-8")
    });
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let task_run_id = CanonicalId::parse(TASK_RUN_ID).expect("task run ID");
    let identity = CommandIdentity::new(
        CanonicalId::parse(COMMAND_ID).expect("command ID"),
        "cancel-1",
    )
    .expect("identity");

    let acknowledgement = client
        .cancel_task_run(CancelTaskRunRequest::new(identity, task_run_id, 4))
        .await
        .expect("cancellation acknowledgement");
    let request = server.await.expect("server");
    assert!(request.starts_with(&format!("POST /v1/task-runs/{TASK_RUN_ID}/cancel HTTP/1.1")));
    assert!(request.contains("authorization: GocodeSession "));
    assert!(request.contains("x-command-id: 018f2e3a-7000-7000-8000-000000000212"));
    assert!(request.contains("idempotency-key: cancel-1"));
    assert!(request.contains("{\"expectedVersion\":4}"));
    assert_eq!(acknowledgement.task_run_id(), task_run_id);
    assert_eq!(acknowledgement.stream_version(), 5);
}

#[tokio::test]
async fn task_run_cancel_rejects_wrong_nonzero_ack_version() {
    let body = format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"streamVersion\":6,\"transition\":\"cancellation_requested\",\"attemptId\":null,\"terminalResult\":null}}"
    );
    let error = cancel_task_run_result(4, &body)
        .await
        .expect_err("non-successor cancel version must be rejected");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
}

#[tokio::test]
async fn task_run_cancel_rejects_version_overflow() {
    let client =
        mock_authenticated_runtime_client("http://127.0.0.1:1", session()).expect("client");
    let error = client
        .cancel_task_run(CancelTaskRunRequest::new(
            CommandIdentity::new(CanonicalId::parse(COMMAND_ID).unwrap(), "overflow").unwrap(),
            CanonicalId::parse(TASK_RUN_ID).unwrap(),
            u64::MAX,
        ))
        .await
        .expect_err("successor version overflow must be rejected");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidRequest);
}
