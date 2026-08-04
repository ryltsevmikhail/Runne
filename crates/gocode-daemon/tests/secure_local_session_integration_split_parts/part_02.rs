#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_http_headers_are_closed_after_the_read_deadline() {
    let running = RunningDaemon::start().await;
    let connector = pinned_connector(&running.profile_path);
    let tcp = tokio::net::TcpStream::connect(running.address)
        .await
        .expect("TCP connection");
    let mut stream = connector
        .connect(
            ServerName::IpAddress(rustls::pki_types::IpAddr::V4([127, 0, 0, 1].into())),
            tcp,
        )
        .await
        .expect("pinned TLS handshake");
    stream
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("partial HTTP headers");

    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("header deadline must close the connection");
    assert!(closed.is_err() || closed.is_ok_and(|read| read == 0));
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_tls_handshakes_release_pre_auth_permits_after_timeout() {
    let running = RunningDaemon::start().await;
    let mut stalled_connections = Vec::new();
    for _ in 0..32 {
        stalled_connections.push(
            tokio::net::TcpStream::connect(running.address)
                .await
                .expect("stalled TCP connection"),
        );
    }
    tokio::time::sleep(Duration::from_millis(2_200)).await;

    LocalRuntimeProfile::load(&running.profile_path)
        .expect("profile")
        .connect(Duration::from_secs(5))
        .await
        .expect("legitimate client is admitted after handshake timeout");
    drop(stalled_connections);
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_profile_from_real_restart_is_rejected_before_protected_http() {
    let directory = owner_private::tempdir();
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let profile_path =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");

    let first = DaemonApplication::start(&config)
        .await
        .expect("first launch");
    let stale_profile = LocalRuntimeProfile::load(&profile_path).expect("first profile");
    let (stop_first, stopped_first) = oneshot::channel();
    let first_task = tokio::spawn(first.run(async move {
        stopped_first
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    stop_first.send(()).expect("stop first launch");
    first_task.await.unwrap().unwrap();

    let second = DaemonApplication::start(&config)
        .await
        .expect("second launch");
    let (stop_second, stopped_second) = oneshot::channel();
    let second_task = tokio::spawn(second.run(async move {
        stopped_second
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    assert!(matches!(
        stale_profile.connect(Duration::from_secs(2)).await,
        Err(gocode_runtime_client::LocalRuntimeConnectError::Transport(
            gocode_runtime_client::RuntimeTransportError::PeerIdentityMismatch
        ))
    ));
    LocalRuntimeProfile::load(&profile_path)
        .expect("current profile")
        .connect(Duration::from_secs(5))
        .await
        .expect("current launch session");
    stop_second.send(()).expect("stop second launch");
    second_task.await.unwrap().unwrap();
}

struct RunningDaemon {
    _directory: tempfile::TempDir,
    address: std::net::SocketAddr,
    profile_path: PathBuf,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    async fn start() -> Self {
        let directory = owner_private::tempdir();
        let mut defaults = BuiltInDefaults::new(directory.path());
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let application = DaemonApplication::start(&config)
            .await
            .expect("start daemon");
        let address = application.local_addr().expect("daemon address");
        let profile_path =
            PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(application.run(async move {
            stopped
                .await
                .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
        }));
        Self {
            _directory: directory,
            address,
            profile_path,
            stop,
            task,
        }
    }

    async fn stop(self) {
        self.stop.send(()).expect("stop daemon");
        tokio::time::timeout(Duration::from_secs(15), self.task)
            .await
            .expect("daemon shutdown timeout")
            .expect("daemon task")
            .expect("daemon shutdown");
    }
}

fn pinned_connector(profile_path: &std::path::Path) -> tokio_rustls::TlsConnector {
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(profile_path).expect("profile")).expect("JSON");
    let certificate = STANDARD
        .decode(
            profile["certificateDerBase64"]
                .as_str()
                .expect("certificate DER"),
        )
        .expect("decode certificate");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(certificate))
        .expect("profile root");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}
