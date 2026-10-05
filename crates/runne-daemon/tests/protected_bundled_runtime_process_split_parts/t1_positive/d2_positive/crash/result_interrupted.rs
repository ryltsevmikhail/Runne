use super::super::verify;
use runne_domain::{conversation::ConversationEvent, task_run::TaskRunEvent};
use runne_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(crate) async fn after_durable_result(
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    bus: &std::path::Path,
    root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    read_path: &std::path::Path,
    read_watch: &std::fs::File,
    create_path: &std::path::Path,
    create_watch: &std::fs::File,
) {
    wait_for_barrier("after-terminal").await;
    assert_eq!(verify::result_count(database, task), 1);
    assert_eq!(verify::release_intent_count(database, task), 1);
    assert_eq!(verify::reserved_effect_count(database, task), 1);
    // The caller already drained and asserted the single initial IN_OPEN.
    // From here on, this watcher proves no additional open occurs on restart.
    assert!(read_path.is_file());
    stop_daemon(supervisor);

    let (mut restarted, client) = super::uncertain::restart_same_root(executable, bus, root).await;
    let version = wait_interrupted(&client, database, task, conversation).await;
    assert_retained_result(database, root, task, read_watch, create_watch, create_path);
    stop_daemon(&mut restarted);

    let (mut reopened, second) = super::uncertain::restart_same_root(executable, bus, root).await;
    assert_eq!(
        wait_interrupted(&second, database, task, conversation).await,
        version
    );
    assert_retained_result(database, root, task, read_watch, create_watch, create_path);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(
        second
            .get_task_run(task)
            .await
            .expect("stable interrupted TaskRun")
            .stream_version(),
        version,
        "second validated reopen did not continue or duplicate the run"
    );
    reopened.stop().expect("stop second interrupted D2 reopen");
    eprintln!("PASS: D2 saved Result stayed intact and InterruptedByRestart across two reopens");
}

async fn wait_interrupted(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
) -> u64 {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(35);
    loop {
        let snapshot = client
            .get_task_run(task)
            .await
            .expect("read interrupted D2 TaskRun");
        if snapshot.state() == runne_runtime_client::TaskRunState::Failed {
            assert_failure_reasons(database, task, conversation);
            return snapshot.stream_version();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "restart did not stop interrupted run"
        );
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
}

fn assert_retained_result(
    database: &std::path::Path,
    root: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    read_watch: &std::fs::File,
    create_watch: &std::fs::File,
    create_path: &std::path::Path,
) {
    verify::assert_encrypted_results(database, task, 1);
    assert_eq!(verify::invocation_count(database, task), 1);
    assert_eq!(verify::result_count(database, task), 1);
    assert_eq!(verify::release_intent_count(database, task), 1);
    assert_eq!(verify::reserved_effect_count(database, task), 1);
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(read_watch, libc::IN_OPEN),
        0
    );
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );
    assert!(!create_path.exists());
    assert_eq!(
        super::super::super::diagnostic::fixture_count(root, "fixture-provider-request-count"),
        1
    );
}

fn assert_failure_reasons(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
) {
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only interrupted D2 receipt view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let task_payload: Vec<u8> = db.query_row(
        "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence DESC LIMIT 1",
        [task_bytes.as_slice()],
        |row| row.get(0),
    ).expect("read interrupted TaskRun terminal");
    assert!(matches!(
        TaskRunEventCodec.decode(&task_payload),
        Ok(TaskRunEvent::TaskRunFailed { reason }) if reason == "interrupted_by_restart"
    ));
    let conversation_bytes = uuid::Uuid::parse_str(&conversation.to_string())
        .expect("Conversation UUID")
        .into_bytes();
    let payloads = db
        .prepare("SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1")
        .expect("prepare interrupted Conversation events")
        .query_map([conversation_bytes.as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .expect("query interrupted Conversation events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read interrupted Conversation events");
    let terminal_count = payloads.iter().filter(|payload| matches!(
        ConversationEventCodec.decode(payload),
        Ok(ConversationEvent::GenerationFailed { taskrun_id, reason: runne_domain::conversation::GenerationFailureReason::InterruptedByRestart, .. }) if taskrun_id.to_string() == task.to_string()
    )).count();
    assert_eq!(terminal_count, 1, "one exact InterruptedByRestart receipt");
    assert!(!payloads.iter().any(|payload| matches!(
        ConversationEventCodec.decode(payload),
        Ok(ConversationEvent::AssistantMessageAppended { .. })
    )));
}

fn stop_daemon(supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor) {
    let child = supervisor.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
    supervisor
        .test_wait_for_exit(std::time::Duration::from_secs(10))
        .expect("reap exact D2 daemon before reopen");
}

async fn wait_for_barrier(name: &str) {
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("barrier directory");
    let entered = directory.join(format!("{name}.entered"));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while !entered.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name} barrier not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
