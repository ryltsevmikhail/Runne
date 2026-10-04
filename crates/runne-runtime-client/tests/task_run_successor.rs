use runne_runtime_client::{
    CommandIdentity, SupersedeUnknownTaskRunRequest, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const PREDECESSOR: &str = "018f2e3a-7000-7000-8000-000000000305";

#[tokio::test]
async fn successor_acknowledgment_rejects_predecessor_as_successor() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(
            request.contains("POST /v1/task-runs/018f2e3a-7000-7000-8000-000000000305/successor")
        );
        assert!(request.contains("duplicate_execution_and_cost_v1"));
        let body = format!(
            r#"{{"predecessorTaskRunId":"{PREDECESSOR}","taskRunId":"{PREDECESSOR}","streamVersion":2,"transition":"unknown_successor_created","attemptId":null,"terminalResult":null}}"#
        );
        stream.write_all(format!(
            "HTTP/1.1 202 Accepted\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()
        ).as_bytes()).await.unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let identity = CommandIdentity::new(
        runne_runtime_client::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000301").unwrap(),
        "successor-test",
    )
    .unwrap();
    let request = SupersedeUnknownTaskRunRequest::duplicate_execution_and_cost_v1(
        identity,
        runne_runtime_client::CanonicalId::parse(PREDECESSOR).unwrap(),
        4,
    );
    assert!(client.supersede_unknown_task_run(request).await.is_err());
    server.await.unwrap();
}

fn session() -> runne_runtime_client::RuntimeSessionInfo {
    runne_runtime_client::RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: runne_runtime_client::PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|v| (*v).into())
            .collect(),
        authority_id: "authority".into(),
        principal_id: "principal".into(),
        event_log_lineage_id: "lineage".into(),
        daemon_instance_id: "daemon".into(),
        launch_generation: 1,
        session_id: "session".into(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".into(),
        certificate_sha256: "certificate".into(),
        capability_digest: "digest".into(),
    }
}
