use super::verify;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    read_target: &std::path::Path,
    create_target: &std::path::Path,
    read_watch: &std::fs::File,
    create_watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("durable-result barrier directory");
    wait_for_file(&directory.join("after-terminal.entered")).await;
    assert_eq!(verify::result_count(database, task), 1);
    assert_eq!(verify::release_intent_count(database, task), 1);
    assert_eq!(verify::reserved_effect_count(database, task), 1);
    assert_eq!(
        super::super::diagnostic::count_watch_mask(read_watch, libc::IN_OPEN),
        1
    );
    let staging_directory = read_target
        .parent()
        .and_then(std::path::Path::parent)
        .expect("same-filesystem fixture staging directory");
    let replacement =
        staging_directory.join(format!(".d2-stale-result-{}.tmp", uuid::Uuid::now_v7()));
    std::fs::write(&replacement, b"replacement after durable Result\n")
        .expect("write replacement after helper Result was committed");
    std::fs::rename(&replacement, read_target)
        .expect("replace target without opening its watched old inode");
    std::fs::write(directory.join("after-terminal.release"), b"continue")
        .expect("release exact helper continuation barrier");

    let ended = verify::wait_success(client, task, database, runtime_root).await;
    assert_eq!(ended.state(), runne_runtime_client::TaskRunState::Failed);
    super::super::faults::assert_failure_projection(database, task);
    verify::assert_encrypted_results(database, task, 1);
    assert_eq!(verify::invocation_count(database, task), 1);
    assert_eq!(verify::result_count(database, task), 1);
    assert_eq!(verify::reserved_effect_count(database, task), 1);
    assert_eq!(verify::release_intent_count(database, task), 1);
    assert_eq!(
        super::super::diagnostic::count_watch_mask(read_watch, libc::IN_OPEN),
        0,
        "target replacement did not trigger a repeated native read"
    );
    assert_eq!(
        super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );
    assert!(!create_target.exists());
    assert_eq!(
        super::super::diagnostic::fixture_count(runtime_root, "fixture-provider-request-count"),
        1,
        "stale exact target stopped provider continuation"
    );
    eprintln!("PASS: D2 target changed after durable Result, before provider continuation");
}

async fn wait_for_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while !path.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "durable-result barrier not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
