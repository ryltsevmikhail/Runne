#![allow(dead_code)]

//! Shared raw loopback fixture for the `TaskRun` read-only API slice: a
//! hand-rolled HTTP/1.1 server that serves queued canned responses, captures
//! every request with its full body, and exposes canonical session builders.

use std::future::Future;

use runne_runtime_client::{
    AuthenticatedRuntimeClient, REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiError, RuntimeSessionInfo,
    mock_authenticated_runtime_client,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub const TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000210";
pub const OTHER_TASK_RUN_ID: &str = "018f2e3a-7000-7000-8000-000000000213";
pub const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000211";
pub const REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000214";
pub const OTHER_REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000215";
pub const CANARY: &str = "RUNNE-CANARY-9f2e-leak";

/// One canned HTTP/1.1 response served by [`serve`] in FIFO order.
pub struct RawResponse {
    pub status: u16,
    pub reason: &'static str,
    pub content_length_override: Option<usize>,
    pub extra_headers: Vec<(String, String)>,
    pub body: String,
}

impl RawResponse {
    pub fn json(status: u16, reason: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            reason,
            content_length_override: None,
            extra_headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.extra_headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub const fn with_content_length(mut self, value: usize) -> Self {
        self.content_length_override = Some(value);
        self
    }
}

pub fn ok_json(body: impl Into<String>) -> RawResponse {
    RawResponse::json(200, "OK", body)
}

pub fn envelope_body(code: &str, request_id: &str) -> String {
    format!("{{\"code\":\"{code}\",\"requestId\":\"{request_id}\"}}")
}

pub fn error_response(
    status: u16,
    reason: &'static str,
    code: &str,
    request_id: &str,
) -> RawResponse {
    RawResponse::json(status, reason, envelope_body(code, request_id))
        .with_header("x-request-id", request_id)
}

/// 200 response declaring one byte over the 8 MiB canonical response cap.
pub fn oversized_content_length_response() -> RawResponse {
    RawResponse::json(200, "OK", "").with_content_length(8 * 1024 * 1024 + 1)
}

pub fn snapshot_json(
    task_run_id: &str,
    state: &str,
    stream_version: u64,
    active_attempt_id: Option<&str>,
    terminal_result: Option<&str>,
) -> String {
    let attempt = active_attempt_id.map_or_else(|| "null".to_owned(), |id| format!("\"{id}\""));
    let terminal = terminal_result.unwrap_or("null");
    format!(
        "{{\"taskRunId\":\"{task_run_id}\",\"state\":\"{state}\",\"streamVersion\":{stream_version},\"activeAttemptId\":{attempt},\"terminalResult\":{terminal}}}"
    )
}

pub fn list_json(items: &[String]) -> String {
    format!("{{\"taskRuns\":[{}]}}", items.join(","))
}

pub struct CapturedRequest {
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl CapturedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// Reads one request: headers up to the blank line plus the full body as
/// declared by content-length, so request assertions are deterministic.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before request was complete",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let start_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(CapturedRequest {
        start_line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

async fn write_response(stream: &mut TcpStream, response: &RawResponse) -> std::io::Result<()> {
    let content_length = response
        .content_length_override
        .unwrap_or(response.body.len());
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {content_length}\r\n",
        response.status, response.reason
    );
    for (name, value) in &response.extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response.body.as_bytes()).await?;
    stream.flush().await
}

/// Binds one loopback listener and serves every queued response on its own
/// connection. Returns the origin and the handle carrying captured requests.
pub async fn serve(responses: Vec<RawResponse>) -> (String, JoinHandle<Vec<CapturedRequest>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback bind");
    let origin = format!("http://{}", listener.local_addr().expect("local address"));
    let server = tokio::spawn(async move {
        let mut captured = Vec::new();
        for response in responses {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            match read_request(&mut stream).await {
                Ok(request) => captured.push(request),
                Err(_) => break,
            }
            let _ = write_response(&mut stream, &response).await;
            let _ = stream.shutdown().await;
        }
        captured
    });
    (origin, server)
}

/// Drives one client call against the fixture and returns the result together
/// with every captured request.
pub async fn drive<T, Call, Fut>(
    session: RuntimeSessionInfo,
    responses: Vec<RawResponse>,
    call: Call,
) -> (Result<T, RuntimeApiError>, Vec<CapturedRequest>)
where
    Call: FnOnce(AuthenticatedRuntimeClient) -> Fut,
    Fut: Future<Output = Result<T, RuntimeApiError>>,
{
    let (origin, server) = serve(responses).await;
    let client = mock_authenticated_runtime_client(&origin, session).expect("mock client");
    let result = call(client).await;
    let captured = server.await.expect("fixture server");
    (result, captured)
}

pub fn session() -> RuntimeSessionInfo {
    session_with_capabilities(
        REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    )
}

pub fn session_with_capabilities(capabilities: Vec<String>) -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".to_owned(),
        schema_hash: "test".to_owned(),
        runtime_version: "test".to_owned(),
        capabilities,
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
