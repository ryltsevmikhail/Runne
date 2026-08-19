use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use runne_daemon::application::DaemonApplication;
use runne_daemon::bootstrap::bootstrap;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use runne_daemon::lock::LockSet;
use runne_runtime_client::LocalRuntimeProfile;
use runne_store::schema;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_and_shared_client_use_only_peer_authenticated_profile_v2() {
    let directory = owner_private::tempdir();
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let legacy_token_path = directory.path().join("runne-daemon").join("token.json");
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
    let directory = owner_private::tempdir();
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let initial = bootstrap(&config).expect("create pre-upgrade database");
    let initial_authority = initial.authority_id;
    drop(initial);

    let legacy_authority = [0x42; 16];
    let connection = schema::reopen_managed_connection_validated(
        std::path::Path::new(&config.db_path),
        schema::ConnectionMode::ValidatedReopen,
        |connection| {
            if schema::read_authority_id(connection)? == Some(initial_authority) {
                Ok(())
            } else {
                Err(rusqlite::Error::InvalidQuery)
            }
        },
    )
    .expect("open database");
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
async fn completed_tls_connections_are_bounded_for_their_full_http_lifetime() {
    let running = RunningDaemon::start().await;
    let connector = pinned_connector(&running.profile_path);
    let mut idle_tls_connections = Vec::new();
    for _ in 0..64 {
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

    let over_limit_tcp = tokio::net::TcpStream::connect(running.address)
        .await
        .expect("TCP backlog remains available");
    let over_limit = tokio::time::timeout(
        Duration::from_millis(250),
        connector.connect(
            ServerName::IpAddress(rustls::pki_types::IpAddr::V4([127, 0, 0, 1].into())),
            over_limit_tcp,
        ),
    )
    .await;
    assert!(
        over_limit.is_err() || over_limit.is_ok_and(|result| result.is_err()),
        "a sixty-fifth live HTTP connection must not be admitted"
    );

    let mut released = idle_tls_connections.pop().expect("full connection set");
    released.shutdown().await.expect("shutdown released connection");
    drop(released);
    let replacement = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let tcp = tokio::net::TcpStream::connect(running.address)
                .await
                .expect("replacement TCP connection");
            match connector
                .connect(
                    ServerName::IpAddress(rustls::pki_types::IpAddr::V4(
                        [127, 0, 0, 1].into(),
                    )),
                    tcp,
                )
                .await
            {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("released lifetime permit admits a replacement");
    drop(replacement);
    drop(idle_tls_connections);
    running.stop().await;
}
