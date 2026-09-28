use std::time::Duration;

use runne_runtime_client::{RuntimeApiErrorKind, mock_authenticated_runtime_client};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

const REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000308";
const OTHER_REQUEST_ID: &str = "018f2e3a-7000-7000-8000-000000000309";

#[tokio::test]
async fn reconciliation_maps_only_the_closed_error_status_code_pairs() {
    for (status, code, expected) in [
        (409, "command_conflict", RuntimeApiErrorKind::Conflict),
        (
            503,
            "runtime_backpressure",
            RuntimeApiErrorKind::Backpressure,
        ),
        (503, "runtime_unavailable", RuntimeApiErrorKind::Unavailable),
    ] {
        let (origin, server) = serve(status, &headers(REQUEST_ID), &body(code, REQUEST_ID)).await;
        let error = mock_authenticated_runtime_client(&origin, super::session())
            .unwrap()
            .reconcile_command(super::text_request())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), expected);
        assert_eq!(error.request_id(), Some(REQUEST_ID));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn prohibited_input_requires_exact_422_code_and_correlated_canonical_envelope() {
    let (origin, server) = serve_generation(
        422,
        &headers(REQUEST_ID),
        &body("prohibited_secret_material", REQUEST_ID),
    )
    .await;
    let error = mock_authenticated_runtime_client(&origin, super::session())
        .unwrap()
        .generate_text(generation_request())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), RuntimeApiErrorKind::ProhibitedInputRejected);
    assert_eq!(error.request_id(), Some(REQUEST_ID));
    server.await.unwrap();

    for (status, code, response_id, header_id) in [
        (422, "other_error", REQUEST_ID, REQUEST_ID),
        (400, "prohibited_secret_material", REQUEST_ID, REQUEST_ID),
        (
            422,
            "prohibited_secret_material",
            REQUEST_ID,
            OTHER_REQUEST_ID,
        ),
    ] {
        assert_generation_invalid(status, &headers(header_id), &body(code, response_id)).await;
    }
    assert_generation_invalid(422, &headers(REQUEST_ID), "not-json").await;
}

async fn assert_generation_invalid(status: u16, headers: &str, body: &str) {
    let (origin, server) = serve_generation(status, headers, body).await;
    let error = mock_authenticated_runtime_client(&origin, super::session())
        .unwrap()
        .generate_text(generation_request())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
    server.await.unwrap();
}

fn generation_request() -> runne_runtime_client::GenerateTextRequest {
    runne_runtime_client::GenerateTextRequest::new(
        super::identity(),
        runne_runtime_client::CanonicalId::parse("018f2e3a-7000-7000-8000-000000000303").unwrap(),
        1,
        "safe fixture",
    )
    .unwrap()
}

async fn serve_generation(
    status: u16,
    headers: &str,
    body: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let headers = headers.to_owned();
    let body = body.to_owned();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        assert!(request.starts_with(
            "POST /v1/conversations/018f2e3a-7000-7000-8000-000000000303/messages HTTP/1.1"
        ));
        write_response(&mut stream, status, &headers, &body).await;
    });
    (origin, server)
}

#[tokio::test]
async fn reconciliation_rejects_invalid_error_status_code_pairs() {
    for (status, code) in [
        (409, "conversation_conflict"),
        (409, "project_workspace_conflict"),
        (429, "runtime_backpressure"),
        (500, "invariant_violation"),
        (500, "runtime_unavailable"),
        (503, "command_conflict"),
        (409, "runtime_backpressure"),
        (503, "future_error"),
    ] {
        assert_invalid(status, &headers(REQUEST_ID), &body(code, REQUEST_ID)).await;
    }
}

#[tokio::test]
async fn reconciliation_rejects_uncorrelated_or_noncanonical_error_request_ids() {
    assert_invalid(
        409,
        &headers(OTHER_REQUEST_ID),
        &body("command_conflict", REQUEST_ID),
    )
    .await;
    assert_invalid(
        409,
        "cache-control: no-store\r\n",
        &body("command_conflict", REQUEST_ID),
    )
    .await;
    assert_invalid(
        409,
        &headers("malformed"),
        &body("command_conflict", REQUEST_ID),
    )
    .await;
    assert_invalid(
        409,
        &format!(
            "{}x-request-id: {OTHER_REQUEST_ID}\r\n",
            headers(REQUEST_ID)
        ),
        &body("command_conflict", REQUEST_ID),
    )
    .await;
}

#[tokio::test]
async fn reconciliation_rejects_missing_duplicate_or_nonexact_error_cache_control() {
    assert_invalid(
        503,
        &format!("x-request-id: {REQUEST_ID}\r\n"),
        &body("runtime_unavailable", REQUEST_ID),
    )
    .await;
    assert_invalid(
        503,
        &format!("{}cache-control: no-store\r\n", headers(REQUEST_ID)),
        &body("runtime_unavailable", REQUEST_ID),
    )
    .await;
    assert_invalid(
        503,
        &format!("x-request-id: {REQUEST_ID}\r\ncache-control: private, no-store\r\n"),
        &body("runtime_unavailable", REQUEST_ID),
    )
    .await;
}

#[tokio::test]
async fn reconciliation_issues_one_post_without_fallback_after_invalid_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        assert!(request.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
        write_response(
            &mut stream,
            409,
            &headers(REQUEST_ID),
            &body("conversation_conflict", REQUEST_ID),
        )
        .await;
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let error = mock_authenticated_runtime_client(&origin, super::session())
        .unwrap()
        .reconcile_command(super::text_request())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    server.await.unwrap();
}

async fn assert_invalid(status: u16, headers: &str, body: &str) {
    let (origin, server) = serve(status, headers, body).await;
    let error = mock_authenticated_runtime_client(&origin, super::session())
        .unwrap()
        .reconcile_command(super::text_request())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
    server.await.unwrap();
}

async fn serve(status: u16, headers: &str, body: &str) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let headers = headers.to_owned();
    let body = body.to_owned();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        assert!(request.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
        write_response(&mut stream, status, &headers, &body).await;
    });
    (origin, server)
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = [0; 4096];
    let count = stream.read(&mut request).await.unwrap();
    String::from_utf8_lossy(&request[..count]).into_owned()
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    headers: &str,
    body: &str,
) {
    stream.write_all(format!("HTTP/1.1 {status} test\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
}

fn headers(request_id: &str) -> String {
    format!("x-request-id: {request_id}\r\ncache-control: no-store\r\n")
}
fn body(code: &str, request_id: &str) -> String {
    format!(r#"{{"code":"{code}","requestId":"{request_id}"}}"#)
}
