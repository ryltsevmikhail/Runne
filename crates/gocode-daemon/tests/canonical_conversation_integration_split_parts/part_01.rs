#[path = "../support/mod.rs"]
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
