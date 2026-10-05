use super::*;

pub(super) async fn target_changed_before_go(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    target: &std::path::Path,
    watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let approval = flows::wait_approval(client, task, database, runtime_root).await;
    flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "target-change",
    )
    .await
    .expect("approve target before changing it");
    wait_entered("pre-release").await;
    let replacement = target.with_extension("changed");
    std::fs::write(&replacement, b"changed after approval\n").expect("replacement bytes");
    std::fs::rename(&replacement, target).expect("replace approved target before GO");
    assert_eq!(
        std::fs::read(target).expect("read replacement before observation"),
        b"changed after approval\n"
    );
    let replacement_watch = open_watch(target);
    release("pre-release");
    let _ = wait_audit_only(client, task, database, runtime_root).await;
    let state = super::flows::wait_terminal(client, task, database, runtime_root).await;
    assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
    super::database::assert_failure_projection(database, task);
    assert_eq!(
        count_watch_mask(watch, libc::IN_OPEN),
        0,
        "original target inode never opened by native read"
    );
    assert_eq!(
        count_watch_mask(&replacement_watch, libc::IN_OPEN),
        0,
        "replacement target inode never opened by native read"
    );
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(database::invocation_state(database, task), "audit_only");
    assert_eq!(database::local_stop_state(database, task), Some(2));
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    eprintln!("PASS: D2 approved target replacement before GO blocked read ({state:?})");
}

pub(super) async fn target_changed_after_read_exit(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    target: &std::path::Path,
    watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let approval = flows::wait_approval(client, task, database, runtime_root).await;
    flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "stale-after-read",
    )
    .await
    .expect("approve read before stale verification case");
    wait_entered("after-exit").await;
    assert_eq!(
        count_watch_mask(watch, libc::IN_OPEN),
        1,
        "helper really read target"
    );
    let replacement = target.with_extension("stale");
    std::fs::write(&replacement, b"target changed after helper exit\n")
        .expect("replacement target contents");
    std::fs::rename(&replacement, target).expect("replace target before receipt verification");
    release("after-exit");
    let _ = wait_audit_only(client, task, database, runtime_root).await;
    let state = super::flows::wait_terminal(client, task, database, runtime_root).await;
    assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
    super::database::assert_failure_projection(database, task);
    assert_eq!(
        count_watch_mask(watch, libc::IN_OPEN),
        0,
        "no additional target opens after stale receipt was rejected"
    );
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(database::invocation_state(database, task), "audit_only");
    assert_eq!(database::local_stop_state(database, task), Some(2));
    assert_eq!(database::release_intent_count(database, task), 1);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert_eq!(
        std::fs::read(target).expect("verify replacement target content"),
        b"target changed after helper exit\n"
    );
    eprintln!("PASS: D2 stale target after a real read stayed audit-only");
}

pub(super) async fn truncated_read_result(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let approval = flows::wait_approval(client, task, database, runtime_root).await;
    flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "truncated-read",
    )
    .await
    .expect("approve exact read before truncation test");
    let _ = wait_audit_only(client, task, database, runtime_root).await;
    let state = super::flows::wait_terminal(client, task, database, runtime_root).await;
    assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
    super::database::assert_failure_projection(database, task);
    assert_eq!(
        count_watch_mask(watch, libc::IN_OPEN),
        1,
        "one real helper read"
    );
    assert_eq!(database::invocation_state(database, task), "audit_only");
    assert_eq!(database::truncated_audit_count(database, task), 1);
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1,
        "truncated result is never sent to the provider"
    );
    eprintln!("PASS: D2 real helper read was recorded truncated and never continued");
}

pub(super) async fn wait_entered(name: &str) {
    let dir = barrier_dir();
    let entered = dir.join(format!("{name}.entered"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    while !entered.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "barrier {name} was never reached"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(super) fn release(name: &str) {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(barrier_dir().join(format!("{name}.release")))
        .expect("create one release for the named worker barrier");
}

pub(super) fn barrier_dir() -> std::path::PathBuf {
    std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("parent supplied worker barrier directory")
}

pub(super) async fn wait_audit_only(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::TaskRunState {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let snapshot = client
            .get_task_run(task)
            .await
            .expect("read uncertain TaskRun");
        if database::invocation_state(database, task) == "audit_only" {
            let stable_until = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < stable_until {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let snapshot = client
                    .get_task_run(task)
                    .await
                    .expect("recheck uncertain TaskRun");
                if snapshot.state() == runne_runtime_client::TaskRunState::Cancelled {
                    assert_eq!(
                        fixture_count(runtime_root, "fixture-provider-request-count"),
                        1,
                        "cancel terminalization did not dispatch another provider round"
                    );
                    return snapshot.state();
                }
                assert_eq!(
                    fixture_count(runtime_root, "fixture-provider-request-count"),
                    1
                );
            }
            return snapshot.state();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 did not reach audit-only quarantine: {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

pub(super) async fn wait_cancelled(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::TaskRunState {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = client
            .get_task_run(task)
            .await
            .expect("read cancellation terminal projection");
        if state.state() == runne_runtime_client::TaskRunState::Cancelled {
            return state.state();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "proved local stop did not project cancellation: {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
