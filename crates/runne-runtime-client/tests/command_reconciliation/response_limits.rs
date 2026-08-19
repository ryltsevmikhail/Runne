use runne_runtime_client::{RuntimeApiErrorKind, mock_authenticated_runtime_client};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const SUCCESS_LIMIT: usize = 8 * 1024 * 1024;
const ERROR_LIMIT: usize = 8 * 1024;
const REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000308";

#[tokio::test]
async fn reconciliation_rejects_declared_and_streamed_success_overflow() {
    assert_invalid(declared_response(
        200,
        SUCCESS_LIMIT + 1,
        "cache-control: no-store\r\n",
    ))
    .await;
    assert_invalid(chunked_response(
        200,
        SUCCESS_LIMIT + 1,
        "cache-control: no-store\r\n",
    ))
    .await;
}

#[tokio::test]
async fn reconciliation_rejects_declared_and_streamed_error_overflow() {
    let headers = format!("cache-control: no-store\r\nx-request-id: {REQUEST_ID}\r\n");
    assert_invalid(declared_response(503, ERROR_LIMIT + 1, &headers)).await;
    assert_invalid(chunked_response(503, ERROR_LIMIT + 1, &headers)).await;
}

async fn assert_invalid(response: Vec<u8>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let count = stream.read(&mut request).await.unwrap();
        assert!(
            String::from_utf8_lossy(&request[..count])
                .starts_with("POST /v1/commands/reconcile HTTP/1.1")
        );
        let _ = stream.write_all(&response).await;
    });
    let error = mock_authenticated_runtime_client(&origin, super::session())
        .unwrap()
        .reconcile_command(super::text_request())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
    server.await.unwrap();
}

fn declared_response(status: u16, length: usize, headers: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} test\r\n{headers}content-length: {length}\r\nconnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn chunked_response(status: u16, length: usize, headers: &str) -> Vec<u8> {
    let body = " ".repeat(length);
    let mut response = format!("HTTP/1.1 {status} test\r\n{headers}transfer-encoding: chunked\r\nconnection: close\r\n\r\n{:X}\r\n", body.len()).into_bytes();
    response.extend_from_slice(body.as_bytes());
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    response
}
