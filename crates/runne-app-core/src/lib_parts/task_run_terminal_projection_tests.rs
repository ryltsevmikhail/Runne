use runne_runtime_client::TaskRunState;
use sha2::Digest;

#[test]
fn taskrun_snapshot_fails_closed_when_authority_lags_replayed_history() {
    assert!(ensure_authoritative_task_run_covers_replay(9, 9).is_ok());
    assert!(ensure_authoritative_task_run_covers_replay(10, 9).is_ok());
    assert!(matches!(
        ensure_authoritative_task_run_covers_replay(8, 9),
        Err(AppCoreError::RuntimeUnavailable)
    ));
}

#[tokio::test]
async fn succeeded_workflow_projects_the_authoritative_local_exit_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task_id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000771").unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut request = [0; 2048];
        let count = stream.read(&mut request).await.expect("read request");
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with(&format!("GET /v1/task-runs/{task_id} HTTP/1.1")));
        let body = format!(
            r#"{{"taskRunId":"{task_id}","state":"succeeded","streamVersion":9,"activeAttemptId":null,"terminalResult":{{"type":"failure","reason":"local_command_exit_7"}}}}"#
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("respond");
    });
    let capabilities = runne_runtime_client::REQUIRED_RUNTIME_CAPABILITIES
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(capabilities.len()).unwrap().to_be_bytes());
    for capability in &capabilities {
        digest.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        digest.update(capability.as_bytes());
    }
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        runne_runtime_client::RuntimeSessionInfo {
            profile_id: runne_runtime_client::EXPECTED_BUNDLE_ID.into(),
            schema_hash: runne_runtime_client::GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capabilities,
            authority_id: "authority-taskrun-terminal".into(),
            principal_id: "principal".into(),
            event_log_lineage_id: "lineage-taskrun-terminal".into(),
            daemon_instance_id: "daemon-instance".into(),
            launch_generation: 1,
            session_id: "session-taskrun-terminal".into(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(),
            certificate_sha256: "11".repeat(32),
            capability_digest: hex::encode(digest.finalize()),
        },
    )
    .expect("authenticated client");
    let authoritative = client
        .get_task_run(task_id)
        .await
        .expect("transport snapshot");
    server.await.expect("server");
    assert_eq!(authoritative.state(), TaskRunState::Succeeded);
    assert!(matches!(
        authoritative.terminal_result(),
        Some(runne_runtime_client::TaskRunTerminalResult::Failure { reason })
            if reason == "local_command_exit_7"
    ));
    let projected = task_run_snapshot(
        task_id,
        &authoritative,
        0,
        authoritative.stream_version(),
        Vec::new(),
        TaskRunRecoveryDisposition::Live,
    );
    assert_eq!(projected.state, TaskRunProjectionState::Succeeded);
    assert_eq!(
        projected.terminal,
        Some(TaskRunTerminalDisposition::Failure)
    );
}
