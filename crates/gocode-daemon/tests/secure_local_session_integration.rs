#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::error::DaemonError;
use gocode_runtime_client::LocalRuntimeProfile;
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
