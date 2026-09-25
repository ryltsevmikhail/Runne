pub use std::net::Ipv4Addr;

pub use runne_runtime_client::{
    CancelTaskRunRequest, CanonicalId, CommandIdentity, REQUIRED_RUNTIME_CAPABILITIES,
    RuntimeApiErrorKind, RuntimeSessionInfo, TaskRunState, TaskRunTerminalResult,
    mock_authenticated_runtime_client,
};
pub use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000210";
pub const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000211";
pub const COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000212";

pub async fn cancel_task_run_result(
    expected_version: u64,
    body: &str,
) -> Result<
    runne_runtime_client::TaskRunCancellationAcknowledgement,
    runne_runtime_client::RuntimeApiError,
> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let response = response(202, "Accepted", body);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("read");
            assert_ne!(read, 0, "request headers");
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
    });
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let result = client
        .cancel_task_run(CancelTaskRunRequest::new(
            CommandIdentity::new(
                CanonicalId::parse(COMMAND_ID).unwrap(),
                "cancel-wrong-version",
            )
            .unwrap(),
            CanonicalId::parse(TASK_RUN_ID).unwrap(),
            expected_version,
        ))
        .await;
    server.await.expect("server");
    result
}

pub async fn query_snapshot(body: &str) -> runne_runtime_client::TaskRunSnapshot {
    query_snapshot_result(body).await.expect("snapshot")
}

pub fn snapshot_body(state: &str, active_attempt_id: Option<&str>) -> String {
    let active_attempt_id =
        active_attempt_id.map_or_else(|| "null".to_owned(), |id| format!("\"{id}\""));
    format!(
        "{{\"taskRunId\":\"{TASK_RUN_ID}\",\"state\":\"{state}\",\"streamVersion\":4,\"activeAttemptId\":{active_attempt_id},\"terminalResult\":null}}"
    )
}

pub async fn query_snapshot_result(
    body: &str,
) -> Result<runne_runtime_client::TaskRunSnapshot, runne_runtime_client::RuntimeApiError> {
    query_task_run_result(200, "OK", body).await
}

pub async fn query_task_run_result(
    status: u16,
    reason: &str,
    body: &str,
) -> Result<runne_runtime_client::TaskRunSnapshot, runne_runtime_client::RuntimeApiError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let body = body.to_owned();
    let response = response(status, reason, &body);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.expect("request");
            assert_ne!(read, 0, "request headers");
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response");
    });
    mock_authenticated_runtime_client(&origin, session())
        .expect("client")
        .get_task_run(CanonicalId::parse(TASK_RUN_ID).expect("task run ID"))
        .await
}

pub fn response(status: u16, reason: &str, body: &str) -> String {
    let request_id_header = request_id(body)
        .map(|value| format!("x-request-id: {value}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 {status} {reason}\r\n{request_id_header}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn request_id(body: &str) -> Option<&str> {
    let key = "\"requestId\":\"";
    let start = body.find(key)? + key.len();
    let end = body[start..].find('"')?;
    Some(&body[start..start + end])
}

pub fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(),
        schema_hash: "test".to_owned(),
        runtime_version: "test".to_owned(),
        capabilities: REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        authority_id: "authority".to_owned(),
        principal_id: "principal".to_owned(),
        event_log_lineage_id: "lineage".to_owned(),
        daemon_instance_id: "daemon".to_owned(),
        launch_generation: 1,
        session_id: "session".to_owned(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "certificate".to_owned(),
        capability_digest: "digest".to_owned(),
    }
}
