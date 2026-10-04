//! A real CLI subprocess observes a mocked worker terminal receipt. The
//! receipt uses the local-command exit reason while this test isolates CLI
//! process exit mapping from protected local execution (covered by daemon T1).

use super::support::{
    connect_client, exit_code, parse_jsonl_lines, seed_conversation, start_test_daemon, stop_daemon,
};
use base64::Engine as _;
use runne_runtime_client::{AuthenticatedRuntimeClient, CanonicalId};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_subprocess_returns_nonzero_for_succeeded_local_exit_failure_receipt() {
    eprintln!("RUN: CLI subprocess maps local command exit failure to nonzero");
    let mut daemon = start_test_daemon().await;
    let client = connect_client(&daemon.profile).await;
    let (conversation_id, workspace_id) = seed_conversation(&client).await;
    let before: Vec<_> = client
        .list_task_runs()
        .await
        .expect("list task runs before CLI")
        .into_iter()
        .map(|snapshot| snapshot.task_run_id())
        .collect();
    let profile = daemon.profile.to_str().unwrap();
    let conversation = conversation_id.to_string();
    let workspace = workspace_id.to_string();
    let child = Command::new(env!("CARGO_BIN_EXE_runne"))
        .args([
            "--format",
            "jsonl",
            "--profile",
            profile,
            "exec",
            "--conversation-id",
            &conversation,
            "--workspace-id",
            &workspace,
            "--prompt",
            "mock local terminal result",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn real CLI executable");

    let run_id = wait_for_cli_task_run(&client, &before, conversation_id).await;

    let http = pinned_test_http_client(&daemon.profile);
    mark_local_exit_failure(&http, &client, run_id).await;

    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("CLI returns after terminal receipt")
        .expect("collect CLI output");
    assert_ne!(
        exit_code(&output),
        0,
        "local exit 7 must not report success"
    );
    let events = parse_jsonl_lines(&output, "CLI local failure receipt");
    assert!(
        events.iter().any(|event| {
            event["type"] == "terminal"
                && event["state"] == "succeeded"
                && event["terminalResult"]["type"] == "failure"
                && event["terminalResult"]["reason"] == "local_command_exit_7"
        }),
        "the real CLI subprocess preserves the failed terminal result: {events:?}"
    );
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());
    stop_daemon(&mut daemon).await;
}

async fn wait_for_cli_task_run(
    client: &AuthenticatedRuntimeClient,
    before: &[CanonicalId],
    conversation_id: CanonicalId,
) -> CanonicalId {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(snapshot) = client
                .list_task_runs()
                .await
                .expect("read task runs while CLI submits")
                .into_iter()
                .find(|snapshot| {
                    snapshot.conversation_id() == Some(conversation_id)
                        && !before.contains(&snapshot.task_run_id())
                })
            {
                break snapshot.task_run_id();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("CLI TaskRun submission appears through the public API")
}

async fn mark_local_exit_failure(
    http: &reqwest::Client,
    client: &AuthenticatedRuntimeClient,
    run_id: CanonicalId,
) {
    let origin = client.test_origin();
    let admitted = post_command(
        http,
        &origin,
        client,
        run_id,
        "admit",
        serde_json::json!({
            "expectedVersion": 2,
        }),
    )
    .await;
    let started_version = admitted["streamVersion"]
        .as_u64()
        .expect("admitted version");
    let started = post_command(
        http,
        &origin,
        client,
        run_id,
        "attempts",
        serde_json::json!({
            "expectedVersion": started_version,
        }),
    )
    .await;
    let running_version = started["streamVersion"].as_u64().expect("running version");
    post_command(
        http,
        &origin,
        client,
        run_id,
        "complete",
        serde_json::json!({
            "expectedVersion": running_version,
            "result": { "type": "failure", "reason": "local_command_exit_7" },
        }),
    )
    .await;
}

fn pinned_test_http_client(profile_path: &std::path::Path) -> reqwest::Client {
    let wire: serde_json::Value =
        serde_json::from_slice(&std::fs::read(profile_path).expect("read test runtime profile"))
            .expect("parse test runtime profile");
    let certificate = base64::engine::general_purpose::STANDARD
        .decode(wire["certificateDerBase64"].as_str().unwrap())
        .expect("decode pinned certificate");
    reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_der(&certificate).unwrap())
        .build()
        .expect("build pinned test HTTP client")
}

async fn post_command(
    http: &reqwest::Client,
    origin: &str,
    client: &AuthenticatedRuntimeClient,
    run_id: CanonicalId,
    action: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let command_id = CanonicalId::now_v7();
    let authorization = format!(
        "GocodeSession {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*client.test_session_authority()),
    );
    let response = http
        .post(format!("{origin}/v1/task-runs/{run_id}/{action}"))
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header("x-command-id", command_id.to_string())
        .header(
            "idempotency-key",
            format!("cli-failure-{action}-{command_id}"),
        )
        .json(&body)
        .send()
        .await
        .expect("send test worker transition");
    let status = response.status();
    let value: serde_json::Value = response.json().await.expect("decode transition ack");
    assert!(
        status.is_success(),
        "test worker transition rejected: {status} {value}"
    );
    value
}
