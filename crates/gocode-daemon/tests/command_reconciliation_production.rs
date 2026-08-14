#![cfg(unix)]

mod support;

use std::{path::PathBuf, time::Duration};

use gocode_daemon::{
    application::DaemonApplication,
    config::{BuiltInDefaults, ConfigurationSnapshot},
    error::DaemonError,
};
use reqwest::{Client, StatusCode};
use rusqlite::Connection;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use support::{TestSession, connect_session};

const PROJECT: &str = "018f2e3a-7000-7000-8000-000000000302";
const WORKSPACE: &str = "018f2e3a-7000-7000-8000-000000000303";
const CONVERSATION: &str = "018f2e3a-7000-7000-8000-000000000304";
const PROJECT_COMMAND: &str = "018f2e3a-7000-7000-8000-000000000311";
const WORKSPACE_COMMAND: &str = "018f2e3a-7000-7000-8000-000000000312";
const CONVERSATION_COMMAND: &str = "018f2e3a-7000-7000-8000-000000000313";
const ABSENT_COMMAND: &str = "018f2e3a-7000-7000-8000-000000000314";

struct RunningDaemon {
    _directory: tempfile::TempDir,
    client: Client,
    authorization: String,
    endpoint: String,
    database: PathBuf,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), DaemonError>>,
}

impl RunningDaemon {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        support::owner_private::secure_directory(directory.path());
        let mut defaults = BuiltInDefaults::new(directory.path());
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let application = DaemonApplication::start(&config).await.unwrap();
        let endpoint = format!("https://{}", application.local_addr().unwrap());
        let database = PathBuf::from(&config.db_path);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(application.run(async move {
            stopped
                .await
                .map_err(|_| DaemonError::Bootstrap("test stop dropped".into()))
        }));
        let TestSession {
            client,
            authorization,
        } = connect_session(&config).await;
        Self {
            _directory: directory,
            client,
            authorization,
            endpoint,
            database,
            stop,
            task,
        }
    }

    async fn post(&self, path: &str, command: &str, key: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.endpoint))
            .header("authorization", &self.authorization)
            .header("x-command-id", command)
            .header("idempotency-key", key)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(15), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn durable_counts(database: &PathBuf) -> [i64; 6] {
    let connection = Connection::open(database).unwrap();
    let count = |table: &str| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    [
        count("projects"),
        count("workspaces"),
        count("events"),
        count("command_receipts"),
        count("project_workspace_command_receipts"),
        count("provider_dispatch_attempts"),
    ]
}

async fn assert_reconciliation(
    daemon: &RunningDaemon,
    command: &str,
    key: &str,
    body: Value,
    expected: Value,
) {
    let response = daemon
        .post("/v1/commands/reconcile", command, key, body)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.json::<Value>().await.unwrap(), expected);
}

async fn assert_unauthenticated_no_store(daemon: &RunningDaemon, body: Vec<u8>) {
    let response = daemon
        .client
        .post(format!("{}/v1/commands/reconcile", daemon.endpoint))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"code": "unauthorized", "requestId": request_id})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_tls_reconciles_shared_project_and_conversation_receipts_without_writes() {
    let daemon = RunningDaemon::start().await;
    assert_unauthenticated_no_store(&daemon, b"{".to_vec()).await;
    assert_unauthenticated_no_store(
        &daemon,
        vec![b'x'; gocode_api::max_message_text_bytes() + 4 * 1024 + 1],
    )
    .await;
    assert_eq!(
        daemon
            .post(
                "/v1/projects",
                PROJECT_COMMAND,
                "project-create",
                json!({"projectId": PROJECT, "displayName": "Project"})
            )
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        daemon
            .post(
                &format!("/v1/projects/{PROJECT}/workspaces"),
                WORKSPACE_COMMAND,
                "workspace-create",
                json!({"workspaceId": WORKSPACE, "displayName": "Workspace"})
            )
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let conversation = daemon
        .post(
            "/v1/conversations",
            CONVERSATION_COMMAND,
            "conversation-create",
            json!({"conversationId": CONVERSATION, "workspaceId": WORKSPACE}),
        )
        .await;
    assert_eq!(conversation.status(), StatusCode::ACCEPTED);
    let conversation = conversation.json::<Value>().await.unwrap();

    let before = durable_counts(&daemon.database);
    assert_eq!(before[5], 0, "setup performs no provider dispatch");
    assert_reconciliation(&daemon, PROJECT_COMMAND, "project-create", json!({"operation": "create_project", "projectId": PROJECT, "displayName": "Project"}), json!({"disposition": "durably_recorded", "outcome": {"operation": "create_project", "projectId": PROJECT, "newVersion": 1}})).await;
    assert_reconciliation(&daemon, CONVERSATION_COMMAND, "conversation-create", json!({"operation": "create_conversation", "conversationId": CONVERSATION, "workspaceId": WORKSPACE}), json!({"disposition": "durably_recorded", "outcome": {"operation": "create_conversation", "conversationId": CONVERSATION, "workspaceId": WORKSPACE, "streamVersion": 1, "committedAt": conversation["committedAt"]}})).await;
    assert_reconciliation(
        &daemon,
        ABSENT_COMMAND,
        "absent",
        json!({"operation": "archive_project", "projectId": PROJECT, "expectedVersion": 1}),
        json!({"disposition": "not_committed_retryable"}),
    )
    .await;
    assert_eq!(
        durable_counts(&daemon.database),
        before,
        "read-only reconciliation must not mutate durable state or provider dispatch inventory"
    );
    daemon.stop().await;
}
