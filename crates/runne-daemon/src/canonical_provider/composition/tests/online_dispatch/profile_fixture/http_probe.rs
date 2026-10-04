use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub(super) struct PostProbe {
    pub(super) address: SocketAddr,
    pub(super) certificate: Vec<u8>,
    pub(super) posts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl PostProbe {
    pub(super) async fn start(host: &str) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut parameters = CertificateParams::new(Vec::new()).unwrap();
        parameters.subject_alt_names = vec![SanType::DnsName(host.try_into().unwrap())];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.self_signed(&key).unwrap();
        let certificate_der = certificate.der().to_vec();
        let mut configuration = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(configuration));
        let posts = Arc::new(AtomicUsize::new(0));
        let task_posts = Arc::clone(&posts);
        let task = tokio::spawn(async move {
            let Ok(Ok((tcp, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            else {
                return;
            };
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut reader = BufReader::new(tls);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_ok() && line.starts_with("POST ") {
                task_posts.fetch_add(1, Ordering::SeqCst);
            }
            let _ = reader.get_mut().write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            ).await;
        });
        Self {
            address,
            certificate: certificate_der,
            posts,
            task,
        }
    }

    pub(super) async fn finish(self) {
        tokio::time::timeout(Duration::from_secs(1), self.task)
            .await
            .expect("loopback probe finishes")
            .expect("probe task");
    }
}
