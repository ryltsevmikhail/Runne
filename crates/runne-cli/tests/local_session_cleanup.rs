//! Repeated short-lived commands must release their own local session.
#![cfg(unix)]
#[allow(dead_code)]
#[path = "task_cli_parts/support.rs"]
mod support;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_cli_commands_do_not_exhaust_local_sessions() {
    let mut daemon = start_test_daemon().await;
    let observer = connect_client(&daemon.profile).await;
    let profile = daemon.profile.to_str().unwrap();
    for index in 0..12 {
        let output = run_cli(&["--profile", profile, "status"]).await;
        assert!(
            output.status.success(),
            "command {index}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        observer
            .list_task_runs()
            .await
            .expect("other live session retained");
    }
    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_cli_commands_release_sessions_and_preserve_error_outcome() {
    let mut daemon = start_test_daemon().await;
    let profile = daemon.profile.to_str().unwrap();
    let unknown = runne_runtime_client::CanonicalId::now_v7().to_string();
    for _ in 0..12 {
        let output = run_cli(&[
            "--format",
            "json",
            "--profile",
            profile,
            "task",
            "get",
            "--task-run-id",
            &unknown,
        ])
        .await;
        assert_eq!(exit_code(&output), 1);
        let envelope = parse_json_error_envelope(&output, "not found");
        assert_eq!(envelope["error"]["code"], "api_error");
        let status = run_cli(&["--profile", profile, "status"]).await;
        assert!(status.status.success());
        assert!(status.stderr.is_empty());
    }
    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_session_limit_still_applies_and_scope_closes_only_its_session() {
    let mut daemon = start_test_daemon().await;
    let mut live = Vec::new();
    for _ in 0..7 {
        live.push(connect_client(&daemon.profile).await);
    }
    let ((), cleanup) = runne_runtime_client::with_local_session_cleanup(async {
        let scoped = connect_client(&daemon.profile).await;
        let rejected = runne_runtime_client::LocalRuntimeProfile::load(&daemon.profile)
            .unwrap()
            .connect(std::time::Duration::from_secs(5))
            .await;
        assert!(
            rejected.is_err(),
            "ninth concurrent session must still be rejected"
        );
        scoped.list_task_runs().await.unwrap();
    })
    .await;
    cleanup.unwrap();
    let replacement = connect_client(&daemon.profile).await;
    replacement.list_task_runs().await.unwrap();
    for client in live {
        client.list_task_runs().await.unwrap();
    }
    stop_daemon(&mut daemon).await;
}
