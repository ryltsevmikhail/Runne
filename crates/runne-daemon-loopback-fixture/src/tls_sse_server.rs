use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, SanType};
use runne_daemon_openai_effect::FixtureRequestAuthenticator;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::fixed_response::SSE_RESPONSE;
use crate::request_validation::{matches_expected_request, request_length};

/// One-use loopback HTTPS endpoint serving the fixture's fixed SSE response.
pub struct TlsSseServer {
    address: SocketAddr,
    certificate_der: Vec<u8>,
    task: tokio::task::JoinHandle<()>,
}

impl TlsSseServer {
    pub const RESPONSE: &str = SSE_RESPONSE;

    pub async fn start(
        runtime_root: &Path,
        authenticator: FixtureRequestAuthenticator,
    ) -> Result<Self, ()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let address = listener.local_addr().map_err(|_| ())?;
        let (certificate_der, config) = tls_config()?;
        let count_path = runtime_root.join("fixture-provider-request-count");
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut stream) = TlsAcceptor::from(config).accept(stream).await else {
                return;
            };
            let Ok(request) = read_request(&mut stream).await else {
                return;
            };
            if !matches_expected_request(&request, &authenticator)
                || increment_request_count(&count_path).is_err()
            {
                return;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                SSE_RESPONSE.len(),
                SSE_RESPONSE
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
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

/// Reads the durable count of exact OpenAI requests accepted by this fixture root.
#[allow(clippy::result_unit_err)]
pub fn request_count(runtime_root: &Path) -> Result<u64, ()> {
    match std::fs::read_to_string(runtime_root.join("fixture-provider-request-count")) {
        Ok(value) => value.trim().parse().map_err(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(()),
    }
}

async fn read_request<S>(stream: &mut S) -> Result<Vec<u8>, ()>
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
        .checked_add(request_length(&request[..headers_end])?)
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
    let count = request_count(path.parent().ok_or(())?)?
        .checked_add(1)
        .ok_or(())?;
    let temporary = temporary_path(path);
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
        std::fs::rename(&temporary, path).map_err(|_| ())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()))
}
