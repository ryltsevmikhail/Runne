//! Integration coverage for serving a caller-composed Axum router.

use axum::{Router, routing::get};
use gocode_daemon::host::{HttpHost, stop_http_host};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn serves_a_supplied_non_health_route() {
    let router = Router::new().route("/canonical", get(|| async { "runtime-ready" }));
    let host = HttpHost::bind("127.0.0.1:0", router).await.unwrap();
    let address = host.local_addr().unwrap();
    let mut host_task = host.start();

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /canonical HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("runtime-ready"), "{response}");

    stop_http_host(&mut host_task).await.unwrap();
}
