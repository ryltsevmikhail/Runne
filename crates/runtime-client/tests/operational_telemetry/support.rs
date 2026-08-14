use std::net::Ipv4Addr;

use gocode_runtime_client::{
    REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiError, RuntimeApiErrorKind,
    RuntimeOperationalTelemetrySnapshotV1, RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

pub const MARKER: &str = "task9-http-rejection-marker";

pub async fn client_for(
    wire: Vec<u8>,
    includes_capability: bool,
    generation: u64,
) -> (
    gocode_runtime_client::AuthenticatedRuntimeClient,
    JoinHandle<FixtureRequest>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fixture listener");
    let origin = format!("http://{}", listener.local_addr().expect("fixture address"));
    let request = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("fixture accept");
        let request = read_request(&mut stream).await;
        stream.write_all(&wire).await.expect("fixture response");
        request
    });
    (
        mock_authenticated_runtime_client(&origin, session(includes_capability, generation))
            .expect("client"),
        request,
    )
}

pub async fn held_status_client(
    status: u16,
) -> (
    gocode_runtime_client::AuthenticatedRuntimeClient,
    oneshot::Receiver<FixtureRequest>,
    oneshot::Sender<()>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fixture listener");
    let origin = format!("http://{}", listener.local_addr().expect("fixture address"));
    let (request_sent, request) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("fixture accept");
        let _ = request_sent.send(read_request(&mut stream).await);
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} held\r\ncontent-length: {}\r\n\r\n",
                    MARKER.len()
                )
                .as_bytes(),
            )
            .await
            .expect("headers");
        released.await.expect("release body");
        stream.write_all(MARKER.as_bytes()).await.expect("body");
    });
    (
        mock_authenticated_runtime_client(&origin, session(true, 1)).expect("client"),
        request,
        release,
        server,
    )
}

pub fn session(includes_capability: bool, generation: u64) -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(),
        schema_hash: "test".to_owned(),
        runtime_version: "test".to_owned(),
        capabilities: REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .filter(|value| includes_capability || **value != "runtime.operational-telemetry.v1")
            .map(|value| (*value).to_owned())
            .collect(),
        authority_id: "authority".to_owned(),
        principal_id: "principal".to_owned(),
        event_log_lineage_id: "lineage".to_owned(),
        daemon_instance_id: "daemon".to_owned(),
        launch_generation: generation,
        session_id: "session".to_owned(),
        authorization_epoch: 1,
        sensitivity_ceiling: "sensitive".to_owned(),
        certificate_sha256: "certificate".to_owned(),
        capability_digest: "digest".to_owned(),
    }
}

pub fn valid_snapshot(generation: u64) -> String {
    format!(
        "{{\"schemaVersion\":1,\"observedAtUnixSeconds\":10,\"launchGeneration\":{generation},\"durable\":{{\"meta\":{{\"observedAtUnixSeconds\":10,\"freshness\":\"observed_in_current_cycle\",\"completeness\":\"complete\"}},\"accounting\":{{\"tokens\":{{\"limit\":10,\"reserved\":2,\"settled\":3,\"remaining\":5}},\"costMicroUsd\":{{\"limit\":10,\"reserved\":2,\"settled\":3,\"remaining\":5}}}},\"providerEffectAuthorities\":{{\"activeCount\":1,\"expiredActiveCount\":0,\"nearestUnexpiredExpiryUnixSeconds\":11}},\"providerApprovalLease\":{{\"activeCount\":0,\"expiredActiveCount\":0,\"nearestUnexpiredExpiryUnixSeconds\":null}},\"committedProviderEffects\":{{\"activeCount\":0,\"expiredActiveCount\":0,\"nearestUnexpiredExpiryUnixSeconds\":null}},\"uncertainAttempts\":0}},\"recoveryTransient\":{{\"meta\":{{\"observedAtUnixSeconds\":10,\"freshness\":\"observed_in_current_cycle\",\"completeness\":\"complete\"}},\"status\":\"lower_bound_since_launch\",\"observedOutboxRecoveriesInGeneration\":0,\"droppedEventCount\":0,\"counterSaturated\":false}}}}"
    )
}

pub fn padded_snapshot(generation: u64, length: usize) -> String {
    let mut snapshot = valid_snapshot(generation);
    snapshot.extend(std::iter::repeat_n(' ', length - snapshot.len()));
    snapshot
}

pub fn response(status: u16, headers: &[&str], body: impl AsRef<[u8]>) -> Vec<u8> {
    let mut headers = headers.to_vec();
    headers.extend(["content-type: application/json", "cache-control: no-store"]);
    raw_response(status, &headers, body)
}

pub fn raw_response(status: u16, headers: &[&str], body: impl AsRef<[u8]>) -> Vec<u8> {
    let body = body.as_ref();
    let mut wire = format!("HTTP/1.1 {status} test\r\n").into_bytes();
    for header in headers {
        wire.extend_from_slice(header.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if !headers
        .iter()
        .any(|header| header.starts_with("content-length:"))
    {
        wire.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    wire.extend_from_slice(b"connection: close\r\n\r\n");
    wire.extend_from_slice(body);
    wire
}

pub fn chunked_response(chunks: &[&[u8]]) -> Vec<u8> {
    let mut wire = b"HTTP/1.1 200 test\r\ncontent-type: application/json\r\ncache-control: no-store\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_vec();
    for chunk in chunks {
        wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        wire.extend_from_slice(chunk);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

pub fn assert_static_error(error: &RuntimeApiError, expected: RuntimeApiErrorKind) {
    assert_eq!(error.kind(), expected);
    assert_eq!(error.request_id(), None);
    assert!(!format!("{error:?}").contains(MARKER));
    assert!(!error.to_string().contains(MARKER));
}

pub fn telemetry_error(
    result: Result<RuntimeOperationalTelemetrySnapshotV1, RuntimeApiError>,
) -> RuntimeApiError {
    match result {
        Ok(_) => panic!("telemetry request must fail"),
        Err(error) => error,
    }
}

pub struct FixtureRequest {
    pub path: String,
    pub authorization: String,
}

async fn read_request(stream: &mut TcpStream) -> FixtureRequest {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.expect("fixture read");
        assert!(read > 0, "request headers");
        request.extend_from_slice(&chunk[..read]);
    }
    let headers = String::from_utf8(request).expect("ASCII request headers");
    FixtureRequest {
        path: headers
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_owned(),
        authorization: headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("authorization: ")
                    .or_else(|| line.strip_prefix("Authorization: "))
            })
            .expect("authorization header")
            .to_owned(),
    }
}
