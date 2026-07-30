#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gocode_daemon::application::DaemonApplication;
use gocode_daemon::bootstrap::bootstrap;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::error::DaemonError;
use gocode_daemon::lock::LockSet;
use gocode_runtime_client::LocalRuntimeProfile;
use gocode_store::schema;
use rustls::pki_types::ServerName;
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_and_shared_client_use_only_peer_authenticated_profile_v2() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let legacy_token_path = directory.path().join("gocode-daemon").join("token.json");
    std::fs::create_dir_all(legacy_token_path.parent().expect("legacy token parent"))
        .expect("create legacy token parent");
    let legacy_token = [0x2a; 32];
    std::fs::write(&legacy_token_path, legacy_token).expect("write legacy token");
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let application = DaemonApplication::start(&config)
        .await
        .expect("start daemon");
    let address = application.local_addr().expect("daemon address");
    let profile_path =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));

    let client = LocalRuntimeProfile::load(&profile_path)
        .expect("strict profile v2")
        .connect(Duration::from_secs(5))
        .await
        .expect("peer-authenticated local session");
    assert_eq!(
        client.session_info().launch_generation,
        1,
        "first durable launch generation"
    );

    let old_bearer = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("test client")
        .get(format!("https://{address}/v1/runtime/profile"))
        .bearer_auth(hex::encode(legacy_token))
        .send()
        .await
        .expect("TLS request");
    assert_eq!(old_bearer.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        std::fs::read(&legacy_token_path).expect("legacy token untouched"),
        legacy_token
    );

    stop.send(()).expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), daemon)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_v1_database_upgrades_without_reusing_legacy_authority_or_token() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let initial = bootstrap(&config).expect("create pre-upgrade database");
    drop(initial);

    let legacy_authority = [0x42; 16];
    let connection = schema::open_with_pragmas(&config.db_path).expect("open database");
    connection
        .execute(
            "UPDATE _authority SET authority_id = ?1 WHERE id = 1",
            rusqlite::params![legacy_authority.as_slice()],
        )
        .expect("install production-v1 authority");
    connection
        .execute(
            "DELETE FROM _daemon_info WHERE key = 'local_session_sidecars_v1'",
            [],
        )
        .expect("remove post-v1 migration marker");
    drop(connection);
    let database_path = PathBuf::from(&config.db_path);
    let runtime_directory = database_path
        .parent()
        .and_then(std::path::Path::parent)
        .expect("runtime directory");
    let locks =
        LockSet::acquire_path(&database_path, runtime_directory).expect("acquire metadata lock");
    locks
        .write_metadata(&legacy_authority)
        .expect("install matching production-v1 metadata");
    drop(locks);

    std::fs::remove_file(&config.replay_integrity_key_path)
        .expect("production-v1 has no replay key");
    std::fs::remove_file(database_path.with_file_name("local-session-authority-id"))
        .expect("production-v1 has no local authority sidecar");
    let legacy_token_path = database_path.with_file_name("token.json");
    let legacy_token = [0x2a; 32];
    std::fs::write(&legacy_token_path, legacy_token).expect("legacy bearer marker");

    let application = DaemonApplication::start(&config)
        .await
        .expect("upgrade production-v1 database");
    let profile_path =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&profile_path).expect("profile")).expect("JSON");
    let local_authority = uuid::Uuid::parse_str(
        profile["authorityId"]
            .as_str()
            .expect("profile authority id"),
    )
    .expect("UUID authority");
    assert_eq!(local_authority.get_version_num(), 7);
    assert_ne!(local_authority.as_bytes(), &legacy_authority);
    assert_eq!(std::fs::read(&legacy_token_path).unwrap(), legacy_token);
    assert_ne!(
        std::fs::read(&config.replay_integrity_key_path).expect("provisioned replay key"),
        legacy_token
    );
    assert_eq!(application.authority_id(), legacy_authority);

    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    let client = LocalRuntimeProfile::load(&profile_path)
        .expect("profile v2")
        .connect(Duration::from_secs(5))
        .await
        .expect("upgraded peer-authenticated session");
    assert_eq!(
        client.session_info().authority_id,
        hex::encode(local_authority.as_bytes())
    );
    stop.send(()).expect("stop daemon");
    daemon.await.unwrap().unwrap();

    let restarted = DaemonApplication::start(&config)
        .await
        .expect("restart upgraded database");
    let restarted_profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&profile_path).expect("restarted profile"))
            .expect("restarted JSON");
    assert_eq!(
        restarted_profile["authorityId"].as_str(),
        profile["authorityId"].as_str()
    );
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(restarted.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    stop.send(()).expect("stop restarted daemon");
    daemon.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_tls_handshakes_do_not_hold_pre_auth_permits_for_keepalive() {
    let running = RunningDaemon::start().await;
    let connector = pinned_connector(&running.profile_path);
    let mut idle_tls_connections = Vec::new();
    for _ in 0..32 {
        let tcp = tokio::net::TcpStream::connect(running.address)
            .await
            .expect("TCP connection");
        idle_tls_connections.push(
            connector
                .connect(
                    ServerName::IpAddress(rustls::pki_types::IpAddr::V4([127, 0, 0, 1].into())),
                    tcp,
                )
                .await
                .expect("pinned TLS handshake"),
        );
    }

    LocalRuntimeProfile::load(&running.profile_path)
        .expect("profile")
        .connect(Duration::from_secs(5))
        .await
        .expect("legitimate client is admitted after completed handshakes");
    drop(idle_tls_connections);
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
    let directory = tempfile::tempdir().expect("temporary directory");
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
        let directory = tempfile::tempdir().expect("temporary directory");
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
