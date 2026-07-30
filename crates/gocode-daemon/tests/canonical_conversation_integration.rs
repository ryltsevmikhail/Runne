//! End-to-end contract for durable Conversation messages and local text execution.

mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
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

use support::{TestSession, connect_session};

const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000081";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000082";
const CREATE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000083";
const GENERATE_COMMAND_ID: &str = "018f2e3a-7000-7000-8000-000000000084";

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
    authorization: Option<&str>,
    path: &str,
    command_id: &str,
    idempotency_key: &str,
    body: Value,
) -> Response {
    let request = client
        .post(url(daemon.address, path))
        .header("x-command-id", command_id)
        .header("idempotency-key", idempotency_key)
        .json(&body);
    match authorization {
        Some(authorization) => request.header("authorization", authorization),
        None => request,
    }
    .send()
    .await
    .unwrap()
}

async fn messages(
    client: &Client,
    daemon: &RunningDaemon,
    authorization: &str,
) -> (StatusCode, Value) {
    let response = client
        .get(url(
            daemon.address,
            &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        ))
        .header("authorization", authorization)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn text_generation_is_authenticated_idempotent_durable_and_queryable_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;
    let token = hex::encode(std::fs::read(&config.replay_integrity_key_path).unwrap());
    let client_profile_path =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    #[cfg(unix)]
    {
        let local_profile =
            gocode_runtime_client::LocalRuntimeProfile::load(&client_profile_path).unwrap();
        assert_eq!(local_profile.endpoint().address(), daemon.address);
    }
    assert!(
        !std::fs::read_to_string(&client_profile_path)
            .unwrap()
            .contains(&token),
        "published profile must reference, not contain, the credential"
    );

    let unauthorized_profile = client
        .get(url(daemon.address, "/v1/runtime/profile"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized_profile.status(), StatusCode::UNAUTHORIZED);

    let runtime_profile = client
        .get(url(daemon.address, "/v1/runtime/profile"))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(runtime_profile.status(), StatusCode::OK);
    let runtime_profile = runtime_profile.json::<Value>().await.unwrap();
    assert_eq!(
        runtime_profile["profileId"],
        gocode_runtime::bundle::BUNDLE_ID
    );
    assert_eq!(
        runtime_profile["schemaHash"],
        "dca8e3a64b77171495a5474a4994dcd8c33a715f2d6b492a9fc2d14e30619862"
    );
    assert_eq!(runtime_profile["runtimeVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(runtime_profile["launchGeneration"], 1);

    let unauthorized = command(
        &client,
        &daemon,
        None,
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "conversation-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let event_count: i64 = Connection::open(&config.db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(event_count, 0, "rejected auth must commit no event");

    let created = command(
        &client,
        &daemon,
        Some(&authorization),
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "conversation-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);
    let created: Value = created.json().await.unwrap();
    assert_eq!(created["conversationId"], CONVERSATION_ID);
    assert_eq!(created["workspaceId"], WORKSPACE_ID);
    assert_eq!(created["streamVersion"], 1);

    let generated = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        GENERATE_COMMAND_ID,
        "generate-one",
        json!({
            "expectedVersion": 1,
            "text": "hello",
        }),
    )
    .await;
    assert_eq!(generated.status(), StatusCode::OK);
    let generated: Value = generated.json().await.unwrap();
    assert_eq!(generated["conversationId"], CONVERSATION_ID);
    assert_eq!(generated["conversationStreamVersion"], 3);
    assert_eq!(generated["taskRunStreamVersion"], 5);
    assert_eq!(generated["userMessage"]["role"], "user");
    assert_eq!(generated["userMessage"]["text"], "hello");
    assert_eq!(generated["assistantMessage"]["role"], "assistant");
    assert_eq!(
        generated["assistantMessage"]["text"],
        "GOCODE local response: hello"
    );
    assert_eq!(
        generated["userMessage"]["taskRunId"],
        generated["taskRunId"]
    );
    assert_eq!(
        generated["assistantMessage"]["taskRunId"],
        generated["taskRunId"]
    );

    let (status, timeline) = messages(&client, &daemon, &authorization).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(timeline["conversationId"], CONVERSATION_ID);
    assert_eq!(timeline["streamVersion"], 3);
    assert_eq!(timeline["messages"].as_array().unwrap().len(), 2);
    assert_eq!(timeline["messages"][0], generated["userMessage"]);
    assert_eq!(timeline["messages"][1], generated["assistantMessage"]);

    let retried = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        GENERATE_COMMAND_ID,
        "generate-one",
        json!({
            "expectedVersion": 1,
            "text": "hello",
        }),
    )
    .await;
    assert_eq!(retried.status(), StatusCode::OK);
    assert_eq!(retried.json::<Value>().await.unwrap(), generated);

    let conflict = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        "018f2e3a-7000-7000-8000-000000000085",
        "generate-one",
        json!({
            "expectedVersion": 1,
            "text": "changed",
        }),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        conflict.json::<Value>().await.unwrap()["code"],
        "conversation_conflict"
    );

    let oversized = command(
        &client,
        &daemon,
        Some(&authorization),
        &format!("/v1/conversations/{CONVERSATION_ID}/messages"),
        "018f2e3a-7000-7000-8000-000000000086",
        "generate-oversized",
        json!({
            "expectedVersion": 3,
            "text": "x".repeat(65_537),
        }),
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oversized.json::<Value>().await.unwrap()["code"],
        "message_text_too_large"
    );
    let connection = Connection::open(&config.db_path).unwrap();
    let event_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    let sensitive_event_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE sensitivity = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        event_count, 8,
        "duplicate, conflict, and rejected input must append no events"
    );
    assert_eq!(
        sensitive_event_count, 2,
        "only the user and assistant message events are sensitive"
    );

    let taskrun_id = generated["taskRunId"].as_str().unwrap().to_owned();
    let taskrun = client
        .get(url(daemon.address, &format!("/v1/task-runs/{taskrun_id}")))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(taskrun.status(), StatusCode::OK);
    let taskrun: Value = taskrun.json().await.unwrap();
    assert_eq!(taskrun["state"], "succeeded");
    assert_eq!(taskrun["streamVersion"], 5);

    daemon.stop().await;
    assert!(
        !client_profile_path.exists(),
        "clean shutdown must remove only its published connection profile"
    );

    let restarted = start(&config).await;
    let TestSession {
        client: restarted_client,
        authorization: restarted_authorization,
    } = connect_session(&config).await;
    let (status, restored) =
        messages(&restarted_client, &restarted, &restarted_authorization).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored, timeline);
    let restored_taskrun = restarted_client
        .get(url(
            restarted.address,
            &format!("/v1/task-runs/{taskrun_id}"),
        ))
        .header("authorization", &restarted_authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(restored_taskrun.status(), StatusCode::OK);
    assert_eq!(
        restored_taskrun.json::<Value>().await.unwrap()["state"],
        "succeeded"
    );
    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_replay_handoff_delivers_conversation_created_over_sse() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;
    let aggregate_id = hex::encode(uuid::Uuid::parse_str(CONVERSATION_ID).unwrap().as_bytes());

    let opened = client
        .post(url(daemon.address, "/v1/replay/open-session"))
        .header("authorization", &authorization)
        .json(&json!({
            "aggregateType": "conversation",
            "aggregateId": aggregate_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = opened.json::<Value>().await.unwrap();
    assert_eq!(opened["events"], json!([]));
    assert_eq!(opened["hasMore"], false);
    let session_id = opened["sessionId"].as_str().unwrap();

    let completed = client
        .post(url(
            daemon.address,
            &format!("/v1/replay/{session_id}/complete-catch-up"),
        ))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = client
        .post(url(
            daemon.address,
            &format!("/v1/replay/{session_id}/continue-live"),
        ))
        .header("authorization", &authorization)
        .send()
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);

    let mut stream = client
        .get(url(
            daemon.address,
            &format!("/v1/replay/{session_id}/events"),
        ))
        .header("authorization", &authorization)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);

    let created = command(
        &client,
        &daemon,
        Some(&authorization),
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "replay-conversation-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);

    let delivery = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let chunk = stream
                .chunk()
                .await
                .unwrap()
                .expect("SSE stream must remain open");
            let chunk = String::from_utf8(chunk.to_vec()).unwrap();
            if chunk.contains("event: delivery") {
                break chunk;
            }
        }
    })
    .await
    .expect("live Conversation event must arrive before timeout");

    assert!(delivery.contains("\"aggregateType\":\"conversation\""));
    assert!(delivery.contains(&format!("\"aggregateId\":\"{CONVERSATION_ID}\"")));
    assert!(delivery.contains("\"eventType\":\"conversation.created\""));
    assert!(delivery.contains("\"replayCursor\":\"gocode-replay-cursor-v1."));

    drop(stream);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledged_replay_cursor_reopens_inclusively_after_daemon_restart() {
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory);
    let daemon = start(&config).await;
    let TestSession {
        client,
        authorization,
    } = connect_session(&config).await;
    let aggregate_id = hex::encode(uuid::Uuid::parse_str(CONVERSATION_ID).unwrap().as_bytes());

    let created = command(
        &client,
        &daemon,
        Some(&authorization),
        "/v1/conversations",
        CREATE_COMMAND_ID,
        "replay-restart-create",
        json!({
            "conversationId": CONVERSATION_ID,
            "workspaceId": WORKSPACE_ID,
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::ACCEPTED);

    let opened = client
        .post(url(daemon.address, "/v1/replay/open-session"))
        .header("authorization", &authorization)
        .json(&json!({
            "aggregateType": "conversation",
            "aggregateId": aggregate_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = opened.json::<Value>().await.unwrap();
    let old_session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let acknowledged_cursor = opened["events"][0]["cursor"].as_str().unwrap().to_owned();

    let acknowledged = client
        .post(url(
            daemon.address,
            &format!("/v1/replay/{old_session_id}/acknowledge"),
        ))
        .header("authorization", &authorization)
        .json(&json!({"cursor": acknowledged_cursor}))
        .send()
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    daemon.stop().await;

    let restarted = start(&config).await;
    let TestSession {
        client: restarted_client,
        authorization: restarted_authorization,
    } = connect_session(&config).await;
    let stale_session = restarted_client
        .post(url(
            restarted.address,
            &format!("/v1/replay/{old_session_id}/read-page"),
        ))
        .header("authorization", &restarted_authorization)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale_session.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        stale_session.json::<Value>().await.unwrap()["code"],
        "replay_session_not_found"
    );

    let reopened = restarted_client
        .post(url(restarted.address, "/v1/replay/open-session"))
        .header("authorization", &restarted_authorization)
        .json(&json!({
            "aggregateType": "conversation",
            "aggregateId": aggregate_id,
            "fromCursor": acknowledged_cursor,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reopened.status(), StatusCode::OK);
    let reopened = reopened.json::<Value>().await.unwrap();
    assert_eq!(reopened["events"].as_array().unwrap().len(), 1);
    assert_eq!(reopened["events"][0]["eventType"], "conversation.created");
    assert_eq!(
        reopened["events"][0]["cursor"].as_str().unwrap(),
        acknowledged_cursor
    );

    let new_session_id = reopened["sessionId"].as_str().unwrap();
    let reacknowledged = restarted_client
        .post(url(
            restarted.address,
            &format!("/v1/replay/{new_session_id}/acknowledge"),
        ))
        .header("authorization", &restarted_authorization)
        .json(&json!({"cursor": acknowledged_cursor}))
        .send()
        .await
        .unwrap();
    assert_eq!(reacknowledged.status(), StatusCode::OK);
    restarted.stop().await;
}
