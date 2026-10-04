use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, SanType};
use runne_daemon_openai_effect::FixtureRequestAuthenticator;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::fixed_response::SSE_RESPONSE;
use super::request_validation::{FixtureRequestKind, matches_expected_request, request_length_for};
use super::t1_scan_receipt::write_t1_scan_receipt;

/// One-use loopback HTTPS endpoint serving the fixture's fixed SSE response.
pub struct TlsSseServer {
    address: SocketAddr,
    certificate_der: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

impl TlsSseServer {
    pub(super) async fn start(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
        request_kind: FixtureRequestKind,
    ) -> Result<Self, ()> {
        Self::start_with_scan(runtime_root, authenticator, request_kind, false, false).await
    }

    #[cfg(all(target_os = "linux", feature = "test-support", not(test)))]
    pub(super) async fn start_t1(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
        drop_response: bool,
    ) -> Result<Self, ()> {
        Self::start_with_scan(
            runtime_root,
            authenticator,
            FixtureRequestKind::ServicePointOfUse,
            true,
            drop_response,
        )
        .await
    }

    async fn start_with_scan(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
        request_kind: FixtureRequestKind,
        scan_wire: bool,
        drop_response: bool,
    ) -> Result<Self, ()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let address = listener.local_addr().map_err(|_| ())?;
        let (certificate_der, config) = tls_config()?;
        let count_path = runtime_root.join("fixture-provider-request-count");
        let scan_receipt_path = runtime_root.join("fixture-provider-wire-scan-receipt.json");
        let task = tokio::spawn(async move {
            for _ in 0..3 {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                if scan_wire
                    && increment_named_count(&count_path, "fixture-provider-connection-count")
                        .is_err()
                {
                    return;
                }
                let Ok(mut stream) = TlsAcceptor::from(Arc::clone(&config)).accept(stream).await
                else {
                    return;
                };
                let Ok(request) = read_request(&mut stream, request_kind).await else {
                    return;
                };
                if (!scan_wire
                    && increment_named_count(&count_path, "fixture-provider-connection-count")
                        .is_err())
                    || !matches_expected_request(&request, &authenticator, request_kind)
                    || increment_request_count(&count_path).is_err()
                {
                    return;
                }
                // D1.6 kill matrix: hold the request in flight (b4) after the
                // provider has received it but before any response byte returns.
                hold_for_kill_boundary("b4_dispatch_in_flight").await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    SSE_RESPONSE.len(),
                    SSE_RESPONSE
                );
                if drop_response {
                    if scan_wire
                        && write_t1_scan_receipt(&scan_receipt_path, &request, &[], false).is_err()
                    {
                        return;
                    }
                    return;
                }
                let mut response_written = 0;
                // D1.6 kill matrix: serve the stream in two chunks so the b6
                // boundary can hold the daemon BETWEEN received stream events —
                // a single full-write would let the client complete first.
                let first_chunk = response.len() / 2;
                while response_written < response.len() {
                    if response_written > 0 {
                        hold_for_kill_boundary("b6_between_stream_events").await;
                    }
                    let remaining = &response.as_bytes()[response_written..];
                    let limit = if response_written == 0 && first_chunk > 0 {
                        first_chunk
                    } else {
                        remaining.len()
                    };
                    match stream.write(&remaining[..limit]).await {
                        Ok(0) | Err(_) => break,
                        Ok(written) => response_written += written,
                    }
                }
                if scan_wire
                    && write_t1_scan_receipt(
                        &scan_receipt_path,
                        &request,
                        &response.as_bytes()[..response_written],
                        response_written == response.len(),
                    )
                    .is_err()
                {
                    return;
                }
                let _ = stream.shutdown().await;
            }
        });
        Ok(Self {
            address,
            certificate_der,
            task,
        })
    }

    #[allow(clippy::result_unit_err)]
    pub fn client(&self) -> Result<reqwest::Client, ()> {
        loopback_client(self.address, &self.certificate_der)
    }
}

impl Drop for TlsSseServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn tls_config() -> Result<(Vec<u8>, Arc<rustls::ServerConfig>), ()> {
    let mut params = CertificateParams::new(Vec::new()).map_err(|_| ())?;
    params.subject_alt_names = vec![SanType::DnsName(
        "api.openai.com".try_into().map_err(|_| ())?,
    )];
    let key = KeyPair::generate().map_err(|_| ())?;
    let certificate = params.self_signed(&key).map_err(|_| ())?;
    let certificate_der = certificate.der().to_vec();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| ())?
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .map_err(|_| ())?;
    Ok((certificate_der, Arc::new(config)))
}

/// Builds the only fixture client route; it rejects every non-loopback target.
#[allow(clippy::result_unit_err)]
pub fn loopback_client(address: SocketAddr, certificate_der: &[u8]) -> Result<reqwest::Client, ()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(());
    }
    let certificate = reqwest::Certificate::from_der(certificate_der).map_err(|_| ())?;
    reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .default_headers(reqwest::header::HeaderMap::new())
        .resolve("api.openai.com", address)
        .add_root_certificate(certificate)
        .build()
        .map_err(|_| ())
}

async fn read_request<S>(stream: &mut S, request_kind: FixtureRequestKind) -> Result<Vec<u8>, ()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    const MAX_REQUEST_BYTES: usize = 512 * 1024;
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    let headers_end = loop {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || request.len().saturating_add(read) > MAX_REQUEST_BYTES {
            return Err(());
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let request_length = headers_end
        .checked_add(request_length_for(&request[..headers_end], request_kind)?)
        .ok_or(())?;
    if request_length > MAX_REQUEST_BYTES || request.len() > request_length {
        return Err(());
    }
    while request.len() < request_length {
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || request.len().saturating_add(read) > request_length {
            return Err(());
        }
        request.extend_from_slice(&chunk[..read]);
    }
    Ok(request)
}

fn increment_request_count(path: &Path) -> Result<(), ()> {
    increment_named_count(path, "fixture-provider-request-count")
}

fn increment_named_count(path: &Path, name: &str) -> Result<(), ()> {
    let path = path.parent().ok_or(())?.join(name);
    let count = match std::fs::read_to_string(&path) {
        Ok(value) => value.trim().parse::<u64>().map_err(|_| ())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err(()),
    }
    .checked_add(1)
    .ok_or(())?;
    let temporary = temporary_path(&path);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| ())?;
        use std::io::Write as _;
        file.write_all(count.to_string().as_bytes())
            .map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        drop(file);
        std::fs::rename(&temporary, &path).map_err(|_| ())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()))
}

/// D1.6 kill-matrix handshake inside the loopback fixture: mirrors the store
/// boundary gate (marker write, bounded release wait) so a test can SIGKILL
/// the daemon while the provider request is in flight or between stream
/// events. Test-support-only module.
async fn hold_for_kill_boundary(boundary: &str) {
    use std::time::{Duration, Instant};
    let Ok(target) = std::env::var("RUNNE_TEST_KILL_BOUNDARY") else {
        return;
    };
    if target != boundary {
        return;
    }
    let Some(arm_file) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_ARM") else {
        return;
    };
    if !std::path::Path::new(&arm_file).exists() {
        return;
    }
    let Some(marker) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_MARKER") else {
        return;
    };
    let _ = tokio::fs::write(&marker, boundary.as_bytes()).await;
    let Some(release) = std::env::var_os("RUNNE_TEST_KILL_BOUNDARY_RELEASE") else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::path::Path::new(&release).exists() {
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
