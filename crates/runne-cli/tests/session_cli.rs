//! Live CLI tests for `session list` / `resume`: sessions are derived from
//! the authoritative `TaskRun` list (conversation/workspace binding from the
//! runtime snapshot), never from a client-side registry. Resume projects the
//! committed conversation state without creating a new `TaskRun`.

#![cfg(unix)]

#[path = "session_cli_parts/support.rs"]
mod support;

use support::{
    exit_code, parse_json_error_envelope, run_cli, seed_one_exec_session, seed_two_exec_sessions,
    start_test_daemon, stop_daemon, task_run_count,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_list_is_empty_on_a_fresh_daemon() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();

    let output = run_cli(&["--profile", &profile_arg, "session", "list"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "no sessions\n");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_list_shows_exec_sessions_with_authoritative_order() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let (first_conversation, second_conversation, workspace_id) =
        seed_two_exec_sessions(&daemon.profile).await;

    let output = run_cli(&["--profile", &profile_arg, "session", "list"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The runtime list order is authoritative: first submitted session first.
    let first_index = stdout
        .find(&first_conversation.to_string())
        .expect("first session listed");
    let second_index = stdout
        .find(&second_conversation.to_string())
        .expect("second session listed");
    assert!(first_index < second_index, "authoritative order: {stdout}");
    assert!(stdout.contains(&workspace_id.to_string()), "{stdout}");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_projects_the_session_without_creating_a_task_run() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let (conversation_id, _workspace_id) = seed_one_exec_session(&daemon.profile).await;
    let before = task_run_count(&daemon.profile).await;

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "resume",
        &conversation_id.to_string(),
    ])
    .await;
    assert!(
        output.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let after = task_run_count(&daemon.profile).await;
    assert_eq!(before, after, "resume never creates a new TaskRun");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_last_picks_the_latest_session() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let (_first, second, _workspace_id) = seed_two_exec_sessions(&daemon.profile).await;

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "resume",
        "--last",
    ])
    .await;
    assert!(
        output.status.success(),
        "resume --last failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&second.to_string()),
        "resume --last resolves the authoritative latest session: {stdout}"
    );

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_with_mismatched_workspace_is_typed_refusal() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let (conversation_id, _workspace_id) = seed_one_exec_session(&daemon.profile).await;
    let foreign_workspace = runne_runtime_client::CanonicalId::now_v7().to_string();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "resume",
        &conversation_id.to_string(),
        "--workspace-id",
        &foreign_workspace,
    ])
    .await;
    assert_eq!(exit_code(&output), 1, "workspace mismatch is the api class");
    let envelope = parse_json_error_envelope(&output, "resume workspace mismatch");
    assert_eq!(envelope["error"]["code"], "session_workspace_mismatch");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_last_without_sessions_is_typed_outcome() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "resume",
        "--last",
    ])
    .await;
    assert_eq!(exit_code(&output), 1, "no session is not a success");
    let envelope = parse_json_error_envelope(&output, "resume --last empty");
    assert_eq!(envelope["error"]["code"], "session_not_found");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_of_unknown_session_is_typed_outcome() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let unknown = runne_runtime_client::CanonicalId::now_v7().to_string();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "resume",
        &unknown,
    ])
    .await;
    assert_eq!(exit_code(&output), 1);
    let envelope = parse_json_error_envelope(&output, "resume unknown");
    assert_eq!(envelope["error"]["code"], "session_not_found");

    stop_daemon(&mut daemon).await;
}
