use super::super::verify;
#[path = "unlaunched/oracle.rs"]
mod oracle;
use oracle::{
    BudgetIdentity, assert_claim_assignment, budget_effects_used, expected_effects_used,
    read_budget_identity, read_unlaunched_row,
};

type UnlaunchedRow = (
    String,
    i64,
    bool,
    bool,
    bool,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
);

#[expect(
    clippy::too_many_arguments,
    reason = "The crash proof retains the exact native process, database, target, and reopen handles."
)]
pub(crate) async fn before_unlaunched(
    barrier: Option<&str>,
    expected_state: &str,
    expected_approval_state: i64,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
    runtime_root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    target: &std::path::Path,
    watch: &std::fs::File,
) {
    if let Some(barrier) = barrier {
        super::uncertain::wait_for_barrier(barrier).await;
    }
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only pre-effect D2 invocation view");
    let row =
        read_unlaunched_row(&db, &task_bytes).expect("read exact unlaunched proposal and approval");
    assert_eq!(row.0, expected_state);
    assert_eq!(row.1, 0, "no managed local area was admitted");
    assert!(!row.2, "native release was never started");
    assert!(!row.3, "no managed area exists before lease");
    assert!(!row.4, "no result exists before launch");
    assert_eq!(row.5, expected_approval_state);
    assert_eq!(verify::result_count(database, task), 0);
    assert_eq!(verify::release_intent_count(database, task), 0);
    assert_claim_assignment(database, &task_bytes, &row);
    let budget_identity = read_budget_identity(database, task).expect("durable D2 reservation");
    assert_eq!(
        budget_effects_used(database, task),
        Some(expected_effects_used(expected_state))
    );
    assert_eq!(
        super::super::super::diagnostic::fixture_count(
            runtime_root,
            "fixture-provider-request-count"
        ),
        1
    );
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(watch, libc::IN_OPEN),
        0
    );

    super::uncertain::kill_supervised_daemon(supervisor);
    let (mut first, first_client) =
        super::uncertain::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let first_snapshot = wait_failed(&first_client, task, database, runtime_root).await;
    super::super::super::faults::assert_failure_projection(database, task);
    assert_unlaunched_unchanged(
        database,
        runtime_root,
        task,
        expected_state,
        expected_approval_state,
        &budget_identity,
        watch,
    );
    let version = first_snapshot.stream_version();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        first_client
            .get_task_run(task)
            .await
            .expect("stable first restart")
            .stream_version(),
        version
    );
    super::uncertain::kill_supervised_daemon(&mut first);

    let (mut second, second_client) =
        super::uncertain::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let second_snapshot = second_client
        .get_task_run(task)
        .await
        .expect("second D2 reopen");
    assert_eq!(
        second_snapshot.state(),
        runne_runtime_client::TaskRunState::Failed
    );
    assert_eq!(second_snapshot.stream_version(), version);
    super::super::super::faults::assert_failure_projection(database, task);
    assert_unlaunched_unchanged(
        database,
        runtime_root,
        task,
        expected_state,
        expected_approval_state,
        &budget_identity,
        watch,
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(
        second_client
            .get_task_run(task)
            .await
            .expect("stable second restart")
            .stream_version(),
        version
    );
    assert_eq!(
        std::fs::read(target).expect("read unchanged target after all watch assertions"),
        b"approved fixture bytes\n"
    );
    second.stop().expect("stop second pre-effect D2 reopen");
}

fn assert_unlaunched_unchanged(
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    expected_state: &str,
    expected_approval_state: i64,
    budget_identity: &BudgetIdentity,
    watch: &std::fs::File,
) {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only reopened D2 invocation view");
    let row = read_unlaunched_row(&db, &id).expect("read preserved unlaunched proposal");
    assert_eq!(row.0, expected_state);
    assert_eq!(row.1, 0);
    assert!(!row.2);
    assert!(!row.3);
    assert!(!row.4);
    assert_eq!(row.5, expected_approval_state);
    assert_claim_assignment(database, &id, &row);
    assert_eq!(verify::result_count(database, task), 0);
    assert_eq!(verify::release_intent_count(database, task), 0);
    assert_eq!(
        budget_effects_used(database, task),
        Some(expected_effects_used(expected_state))
    );
    assert_eq!(
        read_budget_identity(database, task).as_ref(),
        Some(budget_identity)
    );
    assert_eq!(
        super::super::super::diagnostic::fixture_count(
            runtime_root,
            "fixture-provider-request-count"
        ),
        1
    );
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(watch, libc::IN_OPEN),
        0
    );
}

async fn wait_failed(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(40);
    loop {
        let snapshot = client
            .get_task_run(task)
            .await
            .expect("read restarted D2 task");
        if snapshot.state() == runne_runtime_client::TaskRunState::Failed {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "unlaunched proposal did not receive explicit restart failure: {}",
            super::super::super::diagnostic::diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
