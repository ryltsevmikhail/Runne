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
    let directory = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("final response hold directory");
    wait_file(&directory.join("provider-final-stop.entered")).await;
    assert_eq!(verify::result_count(database, task), 2);
    let staging_directory = read_target
        .parent()
        .and_then(std::path::Path::parent)
        .expect("same-filesystem fixture staging directory");
    let replacement =
        staging_directory.join(format!(".d2-stale-final-{}.tmp", uuid::Uuid::now_v7()));
    std::fs::write(&replacement, b"changed after both durable results\n")
        .expect("write replacement outside watched inode");
    std::fs::rename(&replacement, read_target).expect("atomically replace approved target");
    std::fs::write(directory.join("provider-final-stop.release"), b"release")
        .expect("release provider FinalStop frame");

    let failed = super::super::faults::wait_terminal(client, task, database, runtime_root).await;
    assert_eq!(failed, runne_runtime_client::TaskRunState::Failed);
    super::super::faults::assert_failure_projection(database, task);
    verify::assert_encrypted_results(database, task, 2);
    assert_eq!(verify::invocation_count(database, task), 2);
    assert_eq!(verify::reserved_effect_count(database, task), 2);
    assert_eq!(verify::release_intent_count(database, task), 2);
    assert_eq!(
        super::super::diagnostic::count_watch_mask(read_watch, libc::IN_OPEN),
        1
    );
    assert_eq!(
        super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );
    assert_eq!(
        std::fs::read(create_target).expect("first create remains"),
        b"created through approved tool\n"
    );
    assert_eq!(
        super::super::diagnostic::fixture_count(runtime_root, "fixture-provider-request-count"),
        3
    );
    eprintln!("PASS: target drift after both Results prevents final-stop success");
}

async fn wait_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    while !path.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "provider FinalStop hold not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
