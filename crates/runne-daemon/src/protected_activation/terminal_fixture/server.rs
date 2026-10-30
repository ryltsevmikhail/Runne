use crate::error::DaemonError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
type Auth = runne_daemon_deepseek_effect::FixtureRequestAuthenticator;
pub(crate) struct Server {
    pub address: SocketAddr,
    pub certificate: Vec<u8>,
    auth: Arc<Mutex<Option<Auth>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    pub async fn start(root: &Path) -> Result<Self, ()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let address = listener.local_addr().map_err(|_| ())?;
        let params =
            rcgen::CertificateParams::new(vec!["api.deepseek.com".into()]).map_err(|_| ())?;
        let key = rcgen::KeyPair::generate().map_err(|_| ())?;
        let certificate = params.self_signed(&key).map_err(|_| ())?.der().to_vec();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| ())?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .map_err(|_| ())?;
        let auth = Arc::new(Mutex::new(None));
        let shared = auth.clone();
        let root = root.to_path_buf();
        let task = tokio::spawn(async move {
            serve(listener, Arc::new(config), shared, root).await;
        });
        Ok(Self {
            address,
            certificate,
            auth,
            task,
        })
    }
    pub fn set_auth(&self, auth: Auth) -> Result<(), DaemonError> {
        *self.auth.lock().map_err(|_| super::error())? = Some(auth);
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn serve(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    auth: Arc<Mutex<Option<Auth>>>,
    root: PathBuf,
) {
    for count in 1..=100 {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(config.clone())
            .accept(stream)
            .await
        else {
            return;
        };
        let request =
            tokio::time::timeout(std::time::Duration::from_secs(20), read(&mut stream)).await;
        let Ok(Ok((headers, body))) = request else {
            return;
        };
        let accepted = {
            let guard = auth.lock().unwrap();
            guard.as_ref().is_some_and(|a| {
                headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                            .map(|(_, v)| v.trim())
                    })
                    .is_some_and(|v| a.matches(v.as_bytes()))
            })
        };
        if !accepted || !headers.starts_with("POST /responses HTTP/1.1") {
            return;
        }
        let Ok(body) = super::responses::body(&body) else {
            return;
        };
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        if std::fs::write(root.join("terminal-fixture-requests"), count.to_string()).is_err() {
            return;
        }
        if stream.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
        let _ = stream.shutdown().await;
    }
}
async fn read(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(String, serde_json::Value), ()> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > 128 * 1024 {
            return Err(());
        }
        if let Some(split) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| ())?;
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                })
                .ok_or(())?;
            if length > 120 * 1024 {
                return Err(());
            }
            if bytes.len() >= split + 4 + length {
                return Ok((
                    headers.to_owned(),
                    serde_json::from_slice(&bytes[split + 4..split + 4 + length])
                        .map_err(|_| ())?,
                ));
            }
        }
    }
}
