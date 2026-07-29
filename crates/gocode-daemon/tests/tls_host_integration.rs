use axum::{Router, routing::get};
use gocode_daemon::host::{TlsHttpHost, stop_tls_http_host};
use gocode_daemon::launch_identity::LaunchIdentity;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn tls_host_serves_only_after_pinned_tls_handshake() {
    let identity = LaunchIdentity::generate(1).unwrap();
    let host = TlsHttpHost::bind(
        "127.0.0.1:0",
        Router::new().route("/health", get(|| async { "ok" })),
        Arc::clone(identity.server_config()),
    )
    .await
    .unwrap();
    assert_eq!(host.pre_auth_handshake_limit(), 32);
    let address = host.local_addr().unwrap();
    let mut task = host.start();
    let mut roots = RootCertStore::empty();
    roots.add(identity.certificate_der()).unwrap();
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::IpAddress(rustls::pki_types::IpAddr::V4([127, 0, 0, 1].into())),
            tcp,
        )
        .await
        .unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.contains("200 OK"));
    assert!(response.ends_with("ok"));
    stop_tls_http_host(&mut task).await.unwrap();
}
