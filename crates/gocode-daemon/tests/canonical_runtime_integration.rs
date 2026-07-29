//! End-to-end proof that the daemon publishes the real durable TaskRun path.

use std::net::SocketAddr;
use std::time::Duration;

use gocode_daemon::application::DaemonApplication;
use gocode_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use gocode_daemon::error::DaemonError;
use reqwest::{Client, Response, StatusCode};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000071";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000072";

struct RunningDaemon {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("daemon shutdown must finish")
            .expect("daemon task must not panic")
            .expect("daemon shutdown must be quiescent");
    }
}

fn test_config(directory: &TempDir) -> ConfigurationSnapshot {
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    ConfigurationSnapshot::from_defaults(&defaults)
}

async fn start(config: &ConfigurationSnapshot) -> RunningDaemon {
    let application = DaemonApplication::start(config).await.unwrap();
    let address = application.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(application.run(async move {
        stopped
            .await
            .map_err(|_| DaemonError::Bootstrap("test shutdown sender dropped".to_owned()))
    }));
    RunningDaemon {
        address,
        stop,
        task,
    }
}

fn url(address: SocketAddr, path: &str) -> String {
    format!("http://{address}{path}")
}

async fn command(
    client: &Client,
    daemon: &RunningDaemon,
    token: &str,
    path: &str,
    sequence: u8,
    idempotency_key: &str,
    body: Value,
) -> Response {
    client
        .post(url(daemon.address, path))
        .bearer_auth(token)
        .header(
            "x-command-id",
            format!("018f2e3a-7000-7000-8000-0000000000{sequence:02x}"),
        )
        .header("idempotency-key", idempotency_key)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn assert_snapshot(
    client: &Client,
    daemon: &RunningDaemon,
    token: &str,
    taskrun_id: &str,
    version: u64,
    state: &str,
) {
    let response = client
        .get(url(daemon.address, &format!("/v1/task-runs/{taskrun_id}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["taskRunId"], taskrun_id);
    assert_eq!(body["streamVersion"], version);
    assert_eq!(body["state"], state);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canonical_lifecycle_is_authenticated_durable_and_restored_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let client = Client::new();
    let token = hex::encode(std::fs::read(&config.token_path).unwrap());

    let unauthenticated = client
        .post(url(daemon.address, "/v1/task-runs"))
        .header("x-command-id", "018f2e3a-7000-7000-8000-000000000001")
        .header("idempotency-key", "unauthenticated")
        .json(&json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let event_count: i64 = Connection::open(&config.db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(event_count, 0, "rejected auth must commit no event");

    let response = command(
        &client,
        &daemon,
        &token,
        "/v1/task-runs",
        2,
        "create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let taskrun_id = response.json::<Value>().await.unwrap()["taskRunId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_snapshot(&client, &daemon, &token, &taskrun_id, 1, "created").await;

    for (sequence, operation, key, version, state) in [
        (3, "queue", "queue", 2, "queued"),
        (4, "admit", "admit", 3, "admitted"),
        (5, "attempts", "attempt", 4, "running"),
    ] {
        let response = command(
            &client,
            &daemon,
            &token,
            &format!("/v1/task-runs/{taskrun_id}/{operation}"),
            sequence,
            key,
            json!({"expectedVersion": version - 1}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_snapshot(&client, &daemon, &token, &taskrun_id, version, state).await;
    }

    let response = command(
        &client,
        &daemon,
        &token,
        &format!("/v1/task-runs/{taskrun_id}/complete"),
        6,
        "complete",
        json!({
            "expectedVersion": 4,
            "result": {"type": "success"},
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_snapshot(&client, &daemon, &token, &taskrun_id, 5, "succeeded").await;

    daemon.stop().await;

    let restarted = start(&config).await;
    assert_snapshot(&client, &restarted, &token, &taskrun_id, 5, "succeeded").await;
    restarted.stop().await;
}
