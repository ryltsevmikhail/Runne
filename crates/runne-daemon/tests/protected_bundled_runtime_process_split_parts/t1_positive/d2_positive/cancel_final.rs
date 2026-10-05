use super::super::diagnostic::fixture_count;
use super::verify;
#[path = "cancel_final/projection.rs"]
mod projection;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    let directory = std::env::var_os("RUNNE_TEST_D2_PROVIDER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("provider response barrier directory");
    let entered = directory.join("provider-final-stop.entered");
    let release = directory.join("provider-final-stop.release");
    wait_file(&entered).await;
    let current = client.get_task_run(task).await.expect("read before cancel");
    let ack = client
        .cancel_task_run(runne_runtime_client::CancelTaskRunRequest::new(
            runne_runtime_client::CommandIdentity::new(
                runne_runtime_client::CanonicalId::now_v7(),
                format!("d2-final-cancel-{}", uuid::Uuid::now_v7()),
            )
            .expect("late provider cancellation identity"),
            task,
            current.stream_version(),
        ))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "durable cancellation failed: {error:?}; {}",
                super::super::diagnostic::diagnostic(database, task, runtime_root)
            )
        });
    let cancelling = client
        .get_task_run(task)
        .await
        .expect("read acknowledged cancellation");
    assert_eq!(cancelling.stream_version(), ack.stream_version());
    assert_eq!(
        cancelling.state(),
        runne_runtime_client::TaskRunState::Cancelling
    );
    std::fs::write(&release, b"release").expect("release final provider response");
    wait_terminal_journal(database, task).await;
    let cancelled_version = wait_cancelled(client, task).await;
    assert_eq!(verify::result_count(database, task), 2);
    assert_eq!(verify::reserved_effect_count(database, task), 2);
    assert_eq!(verify::release_intent_count(database, task), 2);
    verify::assert_encrypted_results(database, task, 2);
    assert_eq!(
        std::fs::read_to_string(runtime_root.join("fixture-provider-request-count"))
            .expect("provider request receipt")
            .trim()
            .parse::<u64>()
            .expect("provider request count"),
        3
    );
    projection::assert_cancelled_projection(
        client,
        database,
        task,
        conversation,
        cancelled_version,
        runtime_root,
    )
    .await;
    reopen_twice(
        supervisor,
        executable,
        session_bus_socket,
        runtime_root,
        database,
        task,
        conversation,
        cancelled_version,
    )
    .await;
    eprintln!("PASS: D2 third-round terminal after cancel stayed audit-only across two reopens");
}

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
async fn reopen_twice(
    active: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    bus: &std::path::Path,
    root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    expected_version: u64,
) {
    let first_version =
        reopen_once(active, executable, bus, root, database, task, conversation).await;
    assert_eq!(
        first_version, expected_version,
        "first reopen preserves terminal head"
    );
    let (mut first, first_client) = super::crash::restart_same_root(executable, bus, root).await;
    assert_stable_cancel(
        &first_client,
        database,
        root,
        task,
        conversation,
        first_version,
    )
    .await;
    first.stop().expect("stop second D2 cancellation reopen");
}

async fn reopen_once(
    active: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    bus: &std::path::Path,
    root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
) -> u64 {
    let child = active.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
    active
        .test_wait_for_exit(std::time::Duration::from_secs(10))
        .expect("reap cancelled D2 daemon");
    let (mut reopened, client) = super::crash::restart_same_root(executable, bus, root).await;
    let version = client
        .get_task_run(task)
        .await
        .expect("first cancelled reopen")
        .stream_version();
    assert_stable_cancel(&client, database, root, task, conversation, version).await;
    projection::assert_forged_claim_history_is_rejected(&client, database, task).await;
    reopened.stop().expect("stop first cancelled D2 reopen");
    version
}

async fn assert_stable_cancel(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &std::path::Path,
    root: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    version: u64,
) {
    let snapshot = client
        .get_task_run(task)
        .await
        .expect("read cancelled D2 TaskRun");
    assert_eq!(
        snapshot.state(),
        runne_runtime_client::TaskRunState::Cancelled
    );
    assert_eq!(snapshot.stream_version(), version);
    assert_eq!(verify::result_count(database, task), 2);
    assert_eq!(verify::reserved_effect_count(database, task), 2);
    assert_eq!(verify::release_intent_count(database, task), 2);
    verify::assert_encrypted_results(database, task, 2);
    assert_eq!(terminal_count(database, task), 3);
    assert_eq!(fixture_count(root, "fixture-provider-request-count"), 3);
    projection::assert_cancelled_projection(client, database, task, conversation, version, root)
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(
        client
            .get_task_run(task)
            .await
            .expect("stable cancelled replay")
            .stream_version(),
        version,
        "reopen did not add a provider round or effect"
    );
}

async fn wait_file(path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
    while !path.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "provider final-stop holdpoint not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn wait_terminal_journal(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
    while terminal_count(database, task) < 3 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "late response terminal was not durably journaled"
        );
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    assert_eq!(
        terminal_count(database, task),
        3,
        "the exact late terminal is journaled once"
    );
}

fn terminal_count(database: &std::path::Path, task: runne_runtime_client::CanonicalId) -> usize {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only journal view");
    db.query_row(
        "SELECT count(*) FROM provider_stream_journal j JOIN provider_execution_admissions a USING(dispatch_attempt_id) WHERE a.taskrun_id=?1 AND j.event_kind=5 AND j.terminal=1",
        [id.as_slice()],
        |row| row.get(0),
    )
    .expect("count authenticated provider terminal receipts")
}

async fn wait_cancelled(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
) -> u64 {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(35);
    loop {
        let snapshot = client
            .get_task_run(task)
            .await
            .expect("read final cancellation state");
        if snapshot.state() == runne_runtime_client::TaskRunState::Cancelled {
            return snapshot.stream_version();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "late response did not settle cancellation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
}
