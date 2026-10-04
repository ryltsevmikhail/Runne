use super::*;

pub(super) struct LocalTaskRunContext<'a> {
    pub(super) client: runne_runtime_client::AuthenticatedRuntimeClient,
    pub(super) conversation_id: runne_runtime_client::CanonicalId,
    pub(super) workspace_id: runne_runtime_client::CanonicalId,
    pub(super) project_directory: &'a Path,
    pub(super) database: &'a Path,
    pub(super) runtime_root: &'a Path,
    pub(super) executable: &'a owner_private::ControlledExecutable,
    pub(super) supervisor: &'a mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
}

pub(super) async fn exercise_automatic_worker(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    live: &mut runne_runtime_client::ReplayLiveSession,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    database: &Path,
) {
    let mut task_runs = Vec::new();
    for (index, prompt) in [(0, "fixture input"), (1, "fixture input")] {
        let command_id = runne_runtime_client::CanonicalId::now_v7();
        let identity = runne_runtime_client::CommandIdentity::new(
            command_id,
            format!("t1-taskrun-{index}-{command_id}"),
        )
        .expect("TaskRun submit command identity");
        let request = runne_runtime_client::SubmitTaskRunRequest::new(
            identity,
            conversation_id,
            workspace_id,
            prompt,
        )
        .expect("valid TaskRun prompt");
        let acknowledgement = client
            .submit_task_run(request)
            .await
            .expect("submit original TaskRun");
        task_runs.push(acknowledgement.task_run_id());
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut last_states = Vec::new();
    loop {
        let mut complete = true;
        last_states.clear();
        for task_run_id in &task_runs {
            let snapshot = client
                .get_task_run(*task_run_id)
                .await
                .expect("read authoritative TaskRun state");
            if snapshot.state() != runne_runtime_client::TaskRunState::Succeeded {
                complete = false;
                last_states.push((*task_run_id, snapshot.state()));
                assert_ne!(
                    snapshot.state(),
                    runne_runtime_client::TaskRunState::Failed,
                    "provider-backed TaskRun must not complete as failed"
                );
            }
        }
        if complete {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "automatic TaskRuns timed out: {last_states:?}; provider requests {:?}; provider connections {:?}; dispatch states {:?}; effect starts {}",
            database
                .parent()
                .and_then(Path::parent)
                .and_then(|root| std::fs::read_to_string(
                    root.join("fixture-provider-request-count")
                )
                .ok()),
            fixture_count(database, "fixture-provider-connection-count"),
            dispatch_states(database),
            effect_start_count(database),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut linked = std::collections::HashSet::new();
    for _ in 0..24 {
        let event = tokio::time::timeout(Duration::from_secs(5), live.next_event())
            .await
            .expect("TaskRun replay timeout")
            .expect("TaskRun conversation event");
        match event {
            runne_runtime_client::ReplayStreamEvent::Delivery(delivery) => {
                if let runne_runtime_client::CanonicalReplayPayload::Conversation(
                    runne_runtime_client::ConversationReplayPayload::MessageAppended {
                        role,
                        task_run_id,
                        text,
                        ..
                    },
                ) = delivery.event().payload()
                    && *role == runne_runtime_client::ConversationMessageRole::Assistant
                    && task_runs.contains(task_run_id)
                {
                    assert_eq!(text, "fixture response");
                    linked.insert(*task_run_id);
                }
                live.acknowledge(&delivery)
                    .await
                    .expect("acknowledge TaskRun conversation event");
            }
            runne_runtime_client::ReplayStreamEvent::Heartbeat => {}
            runne_runtime_client::ReplayStreamEvent::Terminal(_) => break,
        }
        if linked.len() == task_runs.len() {
            break;
        }
    }
    assert_eq!(
        linked.len(),
        2,
        "assistant events link to each submitted TaskRun"
    );

    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("TaskRun database reader");
    let bindings: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_provider_bindings",
            [],
            |row| row.get(0),
        )
        .expect("TaskRun provider binding count");
    let released: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_assignment_occupations
             WHERE state='released' AND release_event_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("released TaskRun capacity count");
    assert_eq!(
        bindings, 2,
        "each submitted TaskRun has its exact provider binding"
    );
    assert_eq!(released, 2, "both completed TaskRuns release node capacity");
}

fn fixture_count(database: &Path, name: &str) -> Option<String> {
    database
        .parent()
        .and_then(Path::parent)
        .and_then(|root| std::fs::read_to_string(root.join(name)).ok())
}

fn effect_start_count(database: &Path) -> i64 {
    let Ok(connection) = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return -1;
    };
    connection
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .unwrap_or(-1)
}

fn dispatch_states(database: &Path) -> Vec<(i64, i64)> {
    let Ok(connection) = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return Vec::new();
    };
    let Ok(mut statement) =
        connection.prepare("SELECT state, COUNT(*) FROM provider_dispatch_attempts GROUP BY state")
    else {
        return Vec::new();
    };
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .and_then(Iterator::collect)
        .unwrap_or_default()
}

pub(super) fn assert_three_settled_dispatches(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("settled TaskRun dispatch reader");
    let (attempts, settled): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(CASE WHEN attempt.state=5
               AND attempt.settlement_digest=outbox.settlement_digest
               AND outbox.settlement_digest=accounting.settlement_digest
               AND length(attempt.settlement_digest)=32 AND outbox.state=2
               AND outbox.applied_at IS NOT NULL THEN 1 END)
             FROM provider_dispatch_attempts attempt
             LEFT JOIN provider_terminal_outbox outbox
               ON outbox.dispatch_attempt_id=attempt.attempt_id
             LEFT JOIN provider_accounting_settlements accounting
               ON accounting.dispatch_attempt_id=attempt.attempt_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("three settled provider dispatches");
    assert_eq!(attempts, 3, "one conversation generation plus two TaskRuns");
    assert_eq!(settled, 3, "every provider dispatch has terminal proof");
}
