use std::{fs, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_daemon::{
    application::DaemonApplication,
    config::{BuiltInDefaults, ConfigurationSnapshot},
    error::DaemonError,
};
use gocode_runtime_client::LocalRuntimeProfile;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::oneshot;

#[path = "tls_counter.rs"]
mod tls_counter;

const PATH: &str = "/v1/runtime/operational-telemetry";

struct Running {
    address: std::net::SocketAddr,
    authorization: String,
    stop: oneshot::Sender<()>,
    daemon: tokio::task::JoinHandle<Result<(), DaemonError>>,
}

impl Running {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut defaults = BuiltInDefaults::new(directory.path());
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let application = DaemonApplication::start(&config).await.unwrap();
        let address = application.local_addr().unwrap();
        let profile_path = std::path::PathBuf::from(&config.replay_integrity_key_path)
            .with_file_name("client-profile.json");
        let (stop, stopped) = oneshot::channel();
        let daemon = tokio::spawn(application.run(async move {
            stopped
                .await
                .map_err(|_| DaemonError::Bootstrap("stop sender dropped".to_owned()))
        }));
        let client = LocalRuntimeProfile::load(&profile_path)
            .unwrap()
            .connect(Duration::from_secs(5))
            .await
            .unwrap();
        let authority = client.test_session_authority();
        Self {
            address,
            authorization: format!(
                "GocodeSession {}",
                URL_SAFE_NO_PAD.encode(authority.as_ref())
            ),
            stop,
            daemon,
        }
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(15), self.daemon)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

async fn assert_static(response: reqwest::Response, marker: &str, status: reqwest::StatusCode) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    assert!(
        !response
            .headers()
            .keys()
            .any(|name| name.as_str().starts_with("access-control-"))
    );
    assert!(!format!("{:?}", response.headers()).contains(marker));
    let body = response.bytes().await.unwrap();
    assert!(body.is_empty());
    assert!(
        !body
            .windows(marker.len())
            .any(|part| part == marker.as_bytes())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_telemetry_rejections_are_static_and_marker_free() {
    let running = Running::start().await;
    let endpoint = format!("https://{}{}", running.address, PATH);
    let marker = "task3-provider-body-marker";
    assert_static(
        client().get(&endpoint).send().await.unwrap(),
        marker,
        reqwest::StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_static(
        client()
            .get(&endpoint)
            .header("authorization", "GocodeSession invalid")
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_static(
        client()
            .get(&endpoint)
            .header("authorization", &running.authorization)
            .body(marker)
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::BAD_REQUEST,
    )
    .await;
    assert_static(
        client()
            .post(&endpoint)
            .header("authorization", &running.authorization)
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
    )
    .await;
    assert_static(
        client()
            .get(&endpoint)
            .header("authorization", &running.authorization)
            .body(vec![
                b'x';
                gocode_api::MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1 + 1
            ])
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    running.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_telemetry_unavailable_response_is_static_and_marker_free() {
    let running = Running::start().await;
    let marker = "task3-raw-error-marker";
    let response = client()
        .get(format!("https://{}{}", running.address, PATH))
        .header("authorization", &running.authorization)
        .send()
        .await
        .unwrap();
    assert_static(response, marker, reqwest::StatusCode::SERVICE_UNAVAILABLE).await;
    running.stop().await;
}

struct CountingUnavailableQuery {
    calls: AtomicUsize,
}

impl gocode_api::OperationalTelemetryQueryPort for CountingUnavailableQuery {
    fn query_operational_telemetry(
        &self,
    ) -> Result<
        gocode_api::RuntimeOperationalTelemetrySnapshotV1,
        gocode_api::OperationalTelemetryQueryErrorV1,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(gocode_api::OperationalTelemetryQueryErrorV1::Unavailable)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_telemetry_status_matrix_queries_only_the_authenticated_empty_get() {
    let query = Arc::new(CountingUnavailableQuery {
        calls: AtomicUsize::new(0),
    });
    let query_port: Arc<dyn gocode_api::OperationalTelemetryQueryPort> = query.clone();
    let identity = gocode_daemon::launch_identity::LaunchIdentity::generate(1).unwrap();
    let (host, authorization) =
        tls_counter::bind_with_counting_query(query_port, Arc::clone(identity.server_config()))
            .await
            .unwrap();
    let endpoint = format!("https://{}{}", host.local_addr().unwrap(), PATH);
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(host.start().run_until(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("counting host stop sender dropped".to_owned()))
    }));
    let marker = "task3-provider-body-marker";

    assert_static(
        client().get(&endpoint).send().await.unwrap(),
        marker,
        reqwest::StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_static(
        client()
            .get(&endpoint)
            .header("authorization", &authorization)
            .body(marker)
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::BAD_REQUEST,
    )
    .await;
    assert_static(
        client()
            .post(&endpoint)
            .header("authorization", &authorization)
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::METHOD_NOT_ALLOWED,
    )
    .await;
    assert_static(
        client()
            .get(&endpoint)
            .header("authorization", &authorization)
            .body(vec![
                b'x';
                gocode_api::MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1 + 1
            ])
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    assert_eq!(query.calls.load(Ordering::SeqCst), 0);

    assert_static(
        client()
            .get(&endpoint)
            .header("authorization", authorization)
            .send()
            .await
            .unwrap(),
        marker,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(query.calls.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
