#![allow(dead_code)]

use runne_runtime_client::{
    AuthenticatedRuntimeClient, PROTECTED_RUNTIME_CAPABILITIES, RuntimeSessionInfo,
    mock_authenticated_runtime_client,
};
use std::future::Future;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

pub const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000410";
pub const COMMAND: &str = "018f2e3a-7000-7000-8000-000000000411";
pub const OTHER_COMMAND: &str = "018f2e3a-7000-7000-8000-000000000412";
pub const REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000413";

pub fn client(origin: &str) -> AuthenticatedRuntimeClient {
    mock_authenticated_runtime_client(origin, session()).unwrap()
}

fn session() -> RuntimeSessionInfo {
    RuntimeSessionInfo {
        profile_id: "gocode-ui-client/2".into(),
        schema_hash: "test".into(),
        runtime_version: "test".into(),
        capabilities: PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).into())
            .collect(),
        authority_id: "authority".into(),
        principal_id: "local-owner".into(),
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

pub struct Response {
    pub status: u16,
    pub body: String,
    pub content_length: Option<usize>,
}

impl Response {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            content_length: None,
        }
    }

    pub const fn truncated(mut self, declared_length: usize) -> Self {
        self.content_length = Some(declared_length);
        self
    }
}

pub enum Action {
    Reply(Response),
    Drop,
}

#[derive(Debug)]
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

pub async fn serve(actions: Vec<Action>) -> (String, JoinHandle<Vec<CapturedRequest>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut captured = Vec::new();
        for action in actions {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            match read_request(&mut stream).await {
                Ok(request) => captured.push(request),
                Err(_) => break,
            }
            if let Action::Reply(response) = action {
                let length = response.content_length.unwrap_or(response.body.len());
                let head = format!(
                    "HTTP/1.1 {} OK\r\ncontent-type: application/json\r\ncontent-length: {length}\r\nx-request-id: {REQUEST_ID}\r\nconnection: close\r\n\r\n",
                    response.status,
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(response.body.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        }
        captured
    });
    (origin, server)
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            break end + 4;
        }
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    let head = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = head.split("\r\n");
    let start_line = lines.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = bytes[header_end..].to_vec();
    while body.len() < length {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..count]);
    }
    Ok(CapturedRequest {
        start_line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

pub async fn drive<T, F, Fut>(
    actions: Vec<Action>,
    call: F,
) -> (
    Result<T, runne_runtime_client::RuntimeApiError>,
    Vec<CapturedRequest>,
)
where
    F: FnOnce(AuthenticatedRuntimeClient) -> Fut,
    Fut: Future<Output = Result<T, runne_runtime_client::RuntimeApiError>>,
{
    let (origin, server) = serve(actions).await;
    let result = call(client(&origin)).await;
    (result, server.await.unwrap())
}
