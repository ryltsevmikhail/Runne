type ProviderFacts = (i64, i64, i64, i64, Option<String>, Vec<String>);

mod terminal_assertions;
mod wait;
use terminal_assertions::{assert_one_cancelled, assert_one_interrupted};
use wait::{wait_cancelled, wait_failed};

#[expect(
    clippy::too_many_arguments,
    reason = "The native restart proof retains exact daemon, database, task, conversation, and target handles."
)]
pub(crate) async fn at_restart_stage(
    stage: &str,
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    bus: &std::path::Path,
    root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    conversation: runne_runtime_client::CanonicalId,
    target: &std::path::Path,
    watch: &std::fs::File,
    cancel_before_restart: bool,
) {
    eprintln!("RUN: D2 restart stage={stage} cancel={cancel_before_restart}");
    let entered = root.join(".runne-test-protected-d2-stage-entered");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(40);
    while !entered.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 crash barrier {stage} was not reached: {}",
            super::super::super::diagnostic::diagnostic(database, task, root)
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        std::fs::read_to_string(&entered).expect("read exact D2 stage marker"),
        stage
    );
    let before = provider_facts(database, task);
    let requests_before =
        super::super::super::diagnostic::fixture_count(root, "fixture-provider-request-count");
    match stage {
        "start_cycle" | "cycle_started" | "context_committed" | "plan_committed" => {
            assert_eq!(before, (0, 0, 0, 0, None, Vec::new()));
            assert_eq!(requests_before, 0, "pre-admission barrier");
        }
        "proposal_received" => {
            assert_eq!(before.0, 1, "one durable provider admission");
            assert!(before.2 > 0, "completed proposal journal is durable");
            assert_eq!(before.3, 1, "one durable terminal outbox row");
            assert_eq!(
                before.4.as_deref(),
                Some("4"),
                "provider proposal completed"
            );
            assert_eq!(requests_before, 1);
        }
        "provider_uncertain" => {
            assert_eq!(before.0, 1, "one provider admission reached transport");
            assert_eq!(
                before.4.as_deref(),
                Some("6"),
                "remote dispatch remains Unknown"
            );
            assert_eq!(requests_before, 1);
        }
        _ => panic!("unexpected D2 crash stage {stage}"),
    }
    assert_eq!(invocation_count(database, task), 0);
    assert_eq!(result_count(database, task), 0);
    assert_eq!(release_count(database, task), 0);
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(watch, libc::IN_OPEN),
        0
    );
    let before_cancel = client
        .get_task_run(task)
        .await
        .expect("read exact held TaskRun head");
    if cancel_before_restart {
        client
            .cancel_task_run(runne_runtime_client::CancelTaskRunRequest::new(
                runne_runtime_client::CommandIdentity::new(
                    runne_runtime_client::CanonicalId::now_v7(),
                    format!("d2-restart-cancel-{}", uuid::Uuid::now_v7()),
                )
                .expect("D2 cancellation identity"),
                task,
                before_cancel.stream_version(),
            ))
            .await
            .expect("persist cancellation before restart");
    }
    let pre_restart = client
        .get_task_run(task)
        .await
        .expect("read TaskRun immediately before SIGKILL");
    super::uncertain::kill_supervised_daemon(supervisor);
    let (mut first, first_client) =
        super::uncertain::restart_same_root(executable, bus, root).await;
    let first_snapshot = if cancel_before_restart {
        wait_cancelled(&first_client, task, database, root).await
    } else {
        wait_failed(&first_client, task, database, root).await
    };
    if !cancel_before_restart
        && matches!(stage, "start_cycle" | "cycle_started" | "context_committed")
    {
        assert_eq!(
            first_snapshot.stream_version(),
            pre_restart.stream_version() + 1,
            "early restart appends only TaskRunFailed, with no fabricated cycle completion"
        );
    }
    assert_eq!(provider_facts(database, task), before);
    assert_eq!(
        super::super::super::diagnostic::fixture_count(root, "fixture-provider-request-count"),
        requests_before
    );
    assert_eq!(invocation_count(database, task), 0);
    assert_eq!(result_count(database, task), 0);
    assert_eq!(release_count(database, task), 0);
    if cancel_before_restart {
        assert_one_cancelled(database, task, conversation);
    } else {
        assert_one_interrupted(database, task, conversation);
    }
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(watch, libc::IN_OPEN),
        0
    );
    let version = first_snapshot.stream_version();
    super::uncertain::kill_supervised_daemon(&mut first);
    let (mut second, second_client) =
        super::uncertain::restart_same_root(executable, bus, root).await;
    let second_snapshot = second_client
        .get_task_run(task)
        .await
        .expect("read second D2 restart state");
    assert_eq!(
        second_snapshot.state(),
        if cancel_before_restart {
            runne_runtime_client::TaskRunState::Cancelled
        } else {
            runne_runtime_client::TaskRunState::Failed
        }
    );
    assert_eq!(second_snapshot.stream_version(), version);
    assert_eq!(provider_facts(database, task), before);
    assert_eq!(
        super::super::super::diagnostic::fixture_count(root, "fixture-provider-request-count"),
        requests_before
    );
    assert_eq!(invocation_count(database, task), 0);
    assert_eq!(result_count(database, task), 0);
    assert_eq!(release_count(database, task), 0);
    if cancel_before_restart {
        assert_one_cancelled(database, task, conversation);
    } else {
        assert_one_interrupted(database, task, conversation);
    }
    assert!(
        !target
            .parent()
            .expect("D2 target directory")
            .join("fixture-created.txt")
            .exists()
    );
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(watch, libc::IN_OPEN),
        0
    );
    second.stop().expect("stop second D2 recovery reopen");
    assert_eq!(
        std::fs::read(target).expect("target bytes stay unchanged"),
        b"approved fixture bytes\n"
    );
    eprintln!(
        "PASS: D2 stage={stage} stopped locally with provider facts stable over two SIGKILL reopens"
    );
}

fn provider_facts(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> ProviderFacts {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only provider fact snapshot");
    let counts = db.query_row(
        "SELECT (SELECT count(*) FROM provider_execution_admissions WHERE taskrun_id=?1),
                (SELECT count(*) FROM taskrun_provider_round_bindings WHERE taskrun_id=?1),
                (SELECT count(*) FROM provider_stream_journal j JOIN provider_execution_admissions a ON a.dispatch_attempt_id=j.dispatch_attempt_id WHERE a.taskrun_id=?1),
                (SELECT count(*) FROM provider_terminal_outbox o JOIN provider_execution_admissions a ON a.dispatch_attempt_id=o.dispatch_attempt_id WHERE a.taskrun_id=?1),
                (SELECT group_concat(d.state) FROM provider_dispatch_attempts d JOIN provider_execution_admissions a ON a.dispatch_attempt_id=d.attempt_id WHERE a.taskrun_id=?1)",
        [id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).expect("read exact D2 provider journal and dispatch facts");
    let mut statement = db.prepare(
        "SELECT fact FROM (
           SELECT 'A:'||hex(dispatch_attempt_id)||':'||hex(semantic_digest)||':'||hex(prepared_digest)||':'||hex(render_digest)||':'||hex(profile_digest) AS fact FROM provider_execution_admissions WHERE taskrun_id=?1
           UNION ALL SELECT 'J:'||hex(j.dispatch_attempt_id)||':'||j.sequence||':'||j.event_kind||':'||j.terminal||':'||hex(j.plaintext_digest)||':'||hex(j.ciphertext) FROM provider_stream_journal j JOIN provider_execution_admissions a ON a.dispatch_attempt_id=j.dispatch_attempt_id WHERE a.taskrun_id=?1
           UNION ALL SELECT 'O:'||hex(o.dispatch_attempt_id)||':'||o.terminal_sequence||':'||o.state||':'||hex(o.plaintext_digest)||':'||hex(o.settlement_digest)||':'||coalesce(hex(o.receipt_digest),'') FROM provider_terminal_outbox o JOIN provider_execution_admissions a ON a.dispatch_attempt_id=o.dispatch_attempt_id WHERE a.taskrun_id=?1
           UNION ALL SELECT 'D:'||hex(d.attempt_id)||':'||d.state||':'||coalesce(hex(d.settlement_digest),'') FROM provider_dispatch_attempts d JOIN provider_execution_admissions a ON a.dispatch_attempt_id=d.attempt_id WHERE a.taskrun_id=?1
         ) ORDER BY fact"
    ).expect("prepare exact provider fact snapshot");
    let facts = statement
        .query_map([id.as_slice()], |row| row.get::<_, String>(0))
        .expect("query provider facts")
        .collect::<Result<Vec<_>, _>>()
        .expect("read exact provider fact snapshot");
    (counts.0, counts.1, counts.2, counts.3, counts.4, facts)
}

fn invocation_count(database: &std::path::Path, task: runne_runtime_client::CanonicalId) -> i64 {
    count(database, task, "taskrun_tool_invocations")
}

fn result_count(database: &std::path::Path, task: runne_runtime_client::CanonicalId) -> i64 {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only result view");
    db.query_row(
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND state='result'",
        [id.as_slice()],
        |row| row.get(0),
    )
    .expect("read tool Result count")
}

fn release_count(database: &std::path::Path, task: runne_runtime_client::CanonicalId) -> i64 {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only effect view");
    db.query_row(
        "SELECT count(*) FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND release_started=1",
        [id.as_slice()],
        |row| row.get(0),
    )
    .expect("read native release intent count")
}

fn count(database: &std::path::Path, task: runne_runtime_client::CanonicalId, table: &str) -> i64 {
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only invocation view");
    let query = format!("SELECT count(*) FROM {table} WHERE taskrun_id=?1");
    db.query_row(&query, [id.as_slice()], |row| row.get(0))
        .expect("read D2 fact count")
}
