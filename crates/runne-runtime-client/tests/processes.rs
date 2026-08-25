use runne_runtime_client::{
    CanonicalId, CommandIdentity, PROTECTED_RUNTIME_CAPABILITIES, ProcessOutputStreamDto,
    ProcessStateDto, RuntimeSessionInfo, StartProcessRequest, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000302";
const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000303";
const ATTEMPT: &str = "018f2e3a-7000-7000-8000-000000000304";
const INVOCATION: &str = "018f2e3a-7000-7000-8000-000000000305";
const PROCESS: &str = "018f2e3a-7000-7000-8000-000000000306";
const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000307";

fn session() -> RuntimeSessionInfo {
    let mut capabilities = PROTECTED_RUNTIME_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    capabilities.push("process.control.v1".to_owned());
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities,
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

#[tokio::test]
async fn process_client_sends_authenticated_start_and_decodes_snapshot() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
        }
        let body = format!(
            "{{\"processId\":\"{PROCESS}\",\"invocationId\":\"{INVOCATION}\",\"workspaceId\":\"{WORKSPACE}\",\"state\":\"running\",\"version\":1,\"nextOutputSequence\":1}}"
        );
        stream
            .write_all(response(202, &body).as_bytes())
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let identity = CommandIdentity::new(CanonicalId::parse(COMMAND).unwrap(), "start-1").unwrap();
    let snapshot = client
        .start_process(StartProcessRequest::new(
            identity,
            CanonicalId::parse(WORKSPACE).unwrap(),
            CanonicalId::parse(TASK_RUN).unwrap(),
            CanonicalId::parse(ATTEMPT).unwrap(),
            CanonicalId::parse(INVOCATION).unwrap(),
        ))
        .await
        .unwrap();
    let request = server.await.unwrap();
    assert!(request.starts_with("POST /v1/processes HTTP/1.1"));
    assert!(request.contains("x-command-id: 018f2e3a-7000-7000-8000-000000000307"));
    assert!(request.contains("idempotency-key: start-1"));
    assert!(request.contains("\"invocationId\":\"018f2e3a-7000-7000-8000-000000000305\""));
    assert_eq!(snapshot.state(), ProcessStateDto::Running);
    assert_eq!(snapshot.process_id(), CanonicalId::parse(PROCESS).unwrap());
}

#[tokio::test]
async fn process_client_rejects_invalid_output_and_requires_capability() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).await.unwrap();
        let body =
            "{\"chunks\":[{\"sequence\":1,\"stream\":\"stdout\",\"text\":\"ok\"}]}".to_owned();
        stream
            .write_all(response(200, &body).as_bytes())
            .await
            .unwrap();
    });
    let client = mock_authenticated_runtime_client(&origin, session()).unwrap();
    let page = client
        .read_process_output(CanonicalId::parse(PROCESS).unwrap(), 0, 10)
        .await
        .unwrap();
    assert_eq!(page.chunks()[0].stream(), ProcessOutputStreamDto::Stdout);
    server.await.unwrap();

    let mut no_capability = session();
    no_capability
        .capabilities
        .retain(|value| value != "process.control.v1");
    let denied = mock_authenticated_runtime_client(&origin, no_capability)
        .unwrap()
        .read_process_output(CanonicalId::parse(PROCESS).unwrap(), 0, 10)
        .await
        .unwrap_err();
    assert_eq!(
        denied.kind(),
        runne_runtime_client::RuntimeApiErrorKind::Incompatible
    );
}

fn response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}
