use std::{fs, time::Duration};

use runne_daemon::{
    application::DaemonApplication,
    config::{BuiltInDefaults, ConfigurationSnapshot},
    error::DaemonError,
};
use runne_runtime_client::{LocalRuntimeProfile, RuntimeApiErrorKind};
use std::os::unix::fs::PermissionsExt as _;
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_tls_session_exposes_unavailable_telemetry_without_startup_failure() {
    let directory = tempfile::tempdir().expect("temporary daemon directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secure temporary daemon directory");
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    let config = ConfigurationSnapshot::from_defaults(&defaults);
    let application = DaemonApplication::start(&config)
        .await
        .expect("start deterministic daemon");
    let address = application.local_addr().expect("daemon address");
    let profile_path = std::path::PathBuf::from(&config.replay_integrity_key_path)
        .with_file_name("client-profile.json");
    let (stop, stopped) = oneshot::channel();
    let daemon = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));

    let unauthenticated = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("TLS client")
        .get(format!(
            "https://{address}/v1/runtime/operational-telemetry"
        ))
        .send()
        .await
        .expect("unauthenticated TLS request");
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthenticated
            .headers()
            .get(reqwest::header::CACHE_CONTROL),
        Some(&reqwest::header::HeaderValue::from_static("no-store"))
    );
    assert!(
        !unauthenticated
            .headers()
            .contains_key("access-control-allow-origin")
    );

    let client = LocalRuntimeProfile::load(&profile_path)
        .expect("runtime profile")
        .connect(Duration::from_secs(5))
        .await
        .expect("authenticated TLS session");
    assert!(
        client
            .session_info()
            .capabilities
            .iter()
            .any(|capability| capability == runne_api::OPERATIONAL_TELEMETRY_CAPABILITY_V1)
    );
    assert!(matches!(
        client.operational_telemetry().await,
        Err(error) if error.kind() == RuntimeApiErrorKind::Unavailable
    ));

    stop.send(()).expect("stop daemon");
    tokio::time::timeout(Duration::from_secs(15), daemon)
        .await
        .expect("daemon shutdown timeout")
        .expect("daemon task")
        .expect("daemon shutdown");
}
