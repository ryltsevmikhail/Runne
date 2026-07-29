//! Integration coverage for the daemon-owned health HTTP host.

use gocode_daemon::host::{HealthHost, stop_health_host};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn configured_listener_stops_accepting_before_drain_stage() {
    let host = HealthHost::bind("127.0.0.1:0").await.unwrap();
    let address = host.local_addr().unwrap();
    let mut host_task = host.start();

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_http_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains("{\"status\":\"ok\""), "{response}");

    stop_health_host(&mut host_task)
        .await
        .expect("host must stop before drain");
    assert_listener_is_not_serving(address).await;
}

#[tokio::test]
async fn partial_connection_receives_no_response_after_host_stop_returns() {
    let host = HealthHost::bind("127.0.0.1:0").await.unwrap();
    let address = host.local_addr().unwrap();
    let mut host_task = host.start();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let health_response = read_http_response(&mut stream).await;
    assert!(health_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(health_response.contains("{\"status\":\"ok\""));

    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost")
        .await
        .unwrap();

    stop_health_host(&mut host_task)
        .await
        .expect("host and all accepted connections must stop before drain");

    let mut response = [0; 1];
    let received = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut response))
        .await
        .expect("partial connection must be closed");
    match received {
        Ok(0) | Err(_) => {}
        Ok(bytes) => panic!("stopped host must not respond to partial request: {bytes} bytes"),
    }
    assert_listener_is_not_serving(address).await;
}

async fn read_http_response(stream: &mut tokio::net::TcpStream) -> String {
    let mut response = Vec::new();
    let expected_len = loop {
        let mut chunk = [0; 1024];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut chunk))
            .await
            .expect("HTTP response read must complete")
            .expect("HTTP response read must succeed");
        assert!(
            read > 0,
            "connection closed before the HTTP response completed"
        );
        response.extend_from_slice(&chunk[..read]);

        let Some(headers_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&response[..headers_end])
            .expect("HTTP response headers must be UTF-8");
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("Content-Length must be numeric")
            })
            .expect("HTTP response must declare Content-Length");
        break headers_end + 4 + content_length;
    };

    while response.len() < expected_len {
        let mut chunk = [0; 1024];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut chunk))
            .await
            .expect("HTTP response body read must complete")
            .expect("HTTP response body read must succeed");
        assert!(
            read > 0,
            "connection closed before Content-Length bytes arrived"
        );
        response.extend_from_slice(&chunk[..read]);
    }
    response.truncate(expected_len);
    String::from_utf8(response).expect("HTTP response must be UTF-8")
}

async fn assert_listener_is_not_serving(address: std::net::SocketAddr) {
    let Ok(Ok(mut stream)) = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::TcpStream::connect(address),
    )
    .await
    else {
        return;
    };

    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let Ok(Ok(())) = tokio::time::timeout(Duration::from_secs(1), stream.write_all(request)).await
    else {
        return;
    };

    let mut response = [0; 1];
    match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut response)).await {
        Ok(Ok(bytes)) if bytes > 0 => {
            panic!("stopped listener must not serve a new health request")
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {}
    }
}
