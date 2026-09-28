//! Live CLI tests for the headless `exec` command: the real binary submits a
//! `TaskRun` through the X2 typed lifecycle and reports the honest bounded
//! outcome. In the DP1 composition no automatic queue worker exists (the
//! automatic lifecycle is X2's remaining effect-start fence / terminal path,
//! slice ruling 2026-09-28), so the bounded wait resolves `task_uncertain`
//! with the observed event stream on stdout; the cancel terminal is covered
//! by the SIGINT tests. Seeding happens through the public runtime client
//! only; the CLI never touches raw HTTP or `SQLite`.

#![cfg(unix)]

#[path = "headless_cli_parts/support.rs"]
mod support;

use support::{
    connect_client, exit_code, parse_json_error_envelope, parse_jsonl_lines, run_cli,
    run_cli_with_stdin, seed_conversation, start_test_daemon, stop_daemon,
};

use std::os::unix::fs::PermissionsExt;

fn exec_arguments(profile_arg: &str, conversation_id: &str, workspace_id: &str) -> Vec<String> {
    vec![
        "--format".to_owned(),
        "jsonl".to_owned(),
        "--profile".to_owned(),
        profile_arg.to_owned(),
        "exec".to_owned(),
        "--conversation-id".to_owned(),
        conversation_id.to_owned(),
        "--workspace-id".to_owned(),
        workspace_id.to_owned(),
        "--prompt".to_owned(),
        "fixture prompt".to_owned(),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_streams_submitted_event_and_resolves_typed_uncertain_without_worker() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let client = connect_client(&daemon.profile).await;
    let (conversation_id, workspace_id) = seed_conversation(&client).await;

    let arguments = exec_arguments(
        &profile_arg,
        &conversation_id.to_string(),
        &workspace_id.to_string(),
    );
    let references: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let output = run_cli(&references).await;

    assert_eq!(
        exit_code(&output),
        5,
        "bounded wait without a terminal outcome is the typed uncertain exit"
    );
    let events = parse_jsonl_lines(&output, "exec jsonl stdout");
    let submitted = events
        .iter()
        .filter(|event| event["type"] == "submitted")
        .count();
    assert_eq!(submitted, 1, "exactly one submitted event: {events:?}");
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "state" && event["state"] == "queued"),
        "the durable queued state is observed: {events:?}"
    );
    assert!(
        !events.iter().any(|event| event["type"] == "terminal"),
        "no terminal event is claimed without a terminal outcome"
    );
    let envelope = parse_json_error_envelope(&output, "exec uncertain");
    assert_eq!(envelope["error"]["code"], "task_uncertain");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_reads_prompt_from_stdin_when_not_a_tty() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let client = connect_client(&daemon.profile).await;
    let (conversation_id, workspace_id) = seed_conversation(&client).await;

    let arguments = vec![
        "--format".to_owned(),
        "jsonl".to_owned(),
        "--profile".to_owned(),
        profile_arg.clone(),
        "exec".to_owned(),
        "--conversation-id".to_owned(),
        conversation_id.to_string(),
        "--workspace-id".to_owned(),
        workspace_id.to_string(),
    ];
    let references: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let output = run_cli_with_stdin(&references, "stdin prompt").await;

    assert_eq!(
        exit_code(&output),
        5,
        "stdin prompt is accepted and the run submits (no automatic worker)"
    );
    let events = parse_jsonl_lines(&output, "exec stdin jsonl");
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "submitted")
            .count(),
        1,
        "stdin-resolved prompt submits exactly one run: {events:?}"
    );

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_with_empty_stdin_prompt_is_usage_error() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();

    let output =
        run_cli_with_stdin(&["--format", "json", "--profile", &profile_arg, "exec"], "").await;
    assert_eq!(exit_code(&output), 2, "empty headless prompt is usage");
    let envelope = parse_json_error_envelope(&output, "exec empty stdin");
    assert_eq!(envelope["error"]["code"], "invalid_arguments");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_requires_conversation_and_workspace_ids() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "exec",
        "--prompt",
        "x",
    ])
    .await;
    assert_eq!(exit_code(&output), 2, "missing ids are invalid arguments");
    let envelope = parse_json_error_envelope(&output, "exec without ids");
    assert_eq!(envelope["error"]["code"], "invalid_arguments");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_unknown_conversation_is_api_error() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let unknown = runne_runtime_client::CanonicalId::now_v7().to_string();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "exec",
        "--conversation-id",
        &unknown,
        "--workspace-id",
        &unknown,
        "--prompt",
        "x",
    ])
    .await;
    assert_eq!(exit_code(&output), 1, "unknown aggregate is the api class");
    let envelope = parse_json_error_envelope(&output, "exec unknown conversation");
    assert_eq!(envelope["error"]["code"], "api_error");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_without_daemon_is_runtime_unavailable() {
    let daemon = start_test_daemon().await;
    // Graceful shutdown deletes the published profile, so a copy pointing at
    // a closed loopback port provides the genuine transport failure (same
    // pattern as the task profile scenarios).
    let copy_directory = tempfile::tempdir().expect("copy directory");
    std::fs::set_permissions(
        copy_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("secure copy directory");
    let profile_copy = copy_directory.path().join("client-profile.json");
    let mut profile_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&daemon.profile).expect("read profile"))
            .expect("profile JSON");
    let secret_copy = copy_directory.path().join("bootstrap.secret");
    std::fs::copy(
        profile_json["bootstrapSecretPath"]
            .as_str()
            .expect("bootstrapSecretPath"),
        &secret_copy,
    )
    .expect("copy bootstrap secret");
    std::fs::set_permissions(&secret_copy, std::fs::Permissions::from_mode(0o600))
        .expect("secure secret copy");
    profile_json["bootstrapSecretPath"] =
        serde_json::Value::String(secret_copy.to_str().expect("secret path").to_owned());
    profile_json["endpoint"] = serde_json::Value::String("https://127.0.0.1:9".to_owned());
    std::fs::write(
        &profile_copy,
        serde_json::to_vec(&profile_json).expect("serialize profile copy"),
    )
    .expect("write profile copy");
    std::fs::set_permissions(&profile_copy, std::fs::Permissions::from_mode(0o600))
        .expect("secure profile copy");
    let profile_copy_arg = profile_copy.to_str().expect("profile copy path").to_owned();
    let dead = runne_runtime_client::CanonicalId::now_v7().to_string();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_copy_arg,
        "exec",
        "--conversation-id",
        &dead,
        "--workspace-id",
        &dead,
        "--prompt",
        "x",
    ])
    .await;
    assert_eq!(exit_code(&output), 1);
    let envelope = parse_json_error_envelope(&output, "exec dead daemon");
    assert_eq!(envelope["error"]["code"], "runtime_unavailable");
}
