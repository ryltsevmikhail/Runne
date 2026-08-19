//! End-to-end proof that the daemon publishes the real durable TaskRun path.

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use runne_daemon::application::DaemonApplication;
use runne_daemon::config::{BuiltInDefaults, ConfigurationSnapshot};
use runne_daemon::error::DaemonError;
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use support::{TestSession, connect_session};

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000071";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000072";
const PROJECT_ID: &str = "018f2e3a-7000-7000-8000-000000000073";

struct RunningDaemon {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), DaemonError>>,
    stop_deadline: Duration,
}

impl RunningDaemon {
    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(self.stop_deadline, self.task)
            .await
            .expect("daemon shutdown must finish")
            .expect("daemon task must not panic")
            .expect("daemon shutdown must be quiescent");
    }
}

fn test_config(directory: &TempDir) -> ConfigurationSnapshot {
    support::owner_private::secure_directory(directory.path());
    let mut defaults = BuiltInDefaults::new(directory.path());
    defaults.http_bind = "127.0.0.1:0".to_owned();
    ConfigurationSnapshot::from_defaults(&defaults)
}

async fn start(config: &ConfigurationSnapshot) -> RunningDaemon {
    let application = DaemonApplication::start(config).await.unwrap();
    let address = application.local_addr().unwrap();
    let stop_deadline = Duration::from_millis(config.shutdown_timeout_ms)
        .checked_mul(3)
        .and_then(|duration| duration.checked_add(Duration::from_secs(5)))
        .expect("test shutdown deadline must fit in Duration");
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
        stop_deadline,
    }
}

fn url(address: SocketAddr, path: &str) -> String {
    format!("https://{address}{path}")
}

async fn command(
    client: &Client,
    daemon: &RunningDaemon,
    authorization: &str,
    path: &str,
    sequence: u8,
    idempotency_key: &str,
    body: Value,
) -> Response {
    client
        .post(url(daemon.address, path))
        .header("authorization", authorization)
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
    authorization: &str,
    taskrun_id: &str,
    version: u64,
    state: &str,
) {
    let response = client
        .get(url(daemon.address, &format!("/v1/task-runs/{taskrun_id}")))
        .header("authorization", authorization)
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
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;

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

    support::seed_project_workspace(
        &client,
        daemon.address,
        &authorization,
        PROJECT_ID,
        WORKSPACE_ID,
    )
    .await;

    let response = command(
        &client,
        &daemon,
        &authorization,
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
    assert_snapshot(&client, &daemon, &authorization, &taskrun_id, 1, "created").await;

    for (sequence, operation, key, version, state) in [
        (3, "queue", "queue", 2, "queued"),
        (4, "admit", "admit", 3, "admitted"),
        (5, "attempts", "attempt", 4, "running"),
    ] {
        let response = command(
            &client,
            &daemon,
            &authorization,
            &format!("/v1/task-runs/{taskrun_id}/{operation}"),
            sequence,
            key,
            json!({"expectedVersion": version - 1}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_snapshot(
            &client,
            &daemon,
            &authorization,
            &taskrun_id,
            version,
            state,
        )
        .await;
    }

    let response = command(
        &client,
        &daemon,
        &authorization,
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
    assert_snapshot(
        &client,
        &daemon,
        &authorization,
        &taskrun_id,
        5,
        "succeeded",
    )
    .await;

    let profile = client
        .get(url(daemon.address, "/v1/runtime/profile"))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    let profile: Value = profile.json().await.unwrap();
    assert_eq!(
        profile["capabilities"],
        json!(runne_runtime::bundle::BASE_RUNTIME_CAPABILITIES)
    );

    let replay = client
        .post(url(daemon.address, "/v1/replay/open-session"))
        .header("authorization", &authorization)
        .json(&json!({
            "aggregateType": "taskRun",
            "aggregateId": taskrun_id,
            "fromCursor": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay: Value = replay.json().await.unwrap();
    let events = replay["events"].as_array().unwrap();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0]["eventType"], "taskRun.created");
    assert_eq!(events[0]["payload"], json!({"type": "taskRun.created"}));
    assert_eq!(events[4]["eventType"], "taskRun.completed");
    assert_eq!(
        events[4]["payload"],
        json!({"type": "taskRun.completed", "outcome": "success", "reason": null})
    );
    assert_eq!(events[0]["replayBindingId"], events[4]["replayBindingId"]);
    for forbidden in [
        "globalPosition",
        "idempotencyKey",
        "actor",
        "integrityProfile",
        "commandId",
    ] {
        assert!(
            events.iter().all(|event| event.get(forbidden).is_none()),
            "daemon replay leaked {forbidden}"
        );
    }

    daemon.stop().await;

    let restarted = start(&config).await;
    let TestSession {
        client: restarted_client,
        authorization: restarted_authorization,
    } = connect_session(&config).await;
    assert_snapshot(
        &restarted_client,
        &restarted,
        &restarted_authorization,
        &taskrun_id,
        5,
        "succeeded",
    )
    .await;
    restarted.stop().await;
}
