use super::super::diagnostic::{count_watch_mask, diagnostic, fixture_count};
use super::{barriers, database, flows};

pub(super) async fn cancel_before_go(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    target: &std::path::Path,
    watch: &std::fs::File,
    database_path: &std::path::Path,
    runtime_root: &std::path::Path,
) {
    let approval = flows::wait_approval(client, task, database_path, runtime_root).await;
    let version = database::taskrun_head(database_path, task);
    flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "cancel-before-go",
    )
    .await
    .expect("approve read before cancel race");
    barriers::wait_entered("pre-release").await;
    assert_eq!(database::taskrun_head(database_path, task), version);
    let acknowledgement = cancel(
        client,
        task,
        version,
        "before-go",
        database_path,
        runtime_root,
    )
    .await;
    let held = client.get_task_run(task).await.expect("read held TaskRun");
    assert_eq!(held.stream_version(), acknowledgement.stream_version());
    assert_eq!(held.state(), runne_runtime_client::TaskRunState::Cancelling);
    assert_ne!(database::local_stop_state(database_path, task), Some(2));
    assert_eq!(database::result_count(database_path, task), 0);
    assert_eq!(count_watch_mask(watch, libc::IN_OPEN), 0);
    barriers::release("pre-release");
    let state = barriers::wait_audit_only(client, task, database_path, runtime_root).await;
    assert!(target.exists());
    assert_eq!(
        count_watch_mask(watch, libc::IN_OPEN),
        0,
        "no GO/read occurred"
    );
    assert_eq!(database::result_count(database_path, task), 0);
    assert_eq!(database::local_stop_state(database_path, task), Some(2));
    assert_eq!(database::release_intent_count(database_path, task), 0);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert!(matches!(
        state,
        runne_runtime_client::TaskRunState::Cancelling
            | runne_runtime_client::TaskRunState::Cancelled
    ));
    assert_eq!(
        barriers::wait_cancelled(client, task, database_path, runtime_root).await,
        runne_runtime_client::TaskRunState::Cancelled,
        "only the observed empty-area proof may terminalize cancellation: {}",
        diagnostic(database_path, task, runtime_root)
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn cancel_after_create_effect(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    created: &std::path::Path,
    create_watch: &std::fs::File,
    database_path: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    let approval = flows::wait_approval(client, task, database_path, runtime_root).await;
    flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "cancel-after-create-effect",
    )
    .await
    .expect("approve create before post-effect cancel race");
    barriers::wait_entered("after-exit").await;
    let version = database::taskrun_head(database_path, task);
    assert!(
        created.is_file(),
        "create_new effect completed before barrier"
    );
    assert_eq!(
        std::fs::read(created).expect("read created content before watching mutation"),
        b"created through approved tool\n"
    );
    assert_eq!(count_watch_mask(create_watch, libc::IN_CREATE), 1);
    let acknowledgement = cancel(
        client,
        task,
        version,
        "after-create",
        database_path,
        runtime_root,
    )
    .await;
    let held = client
        .get_task_run(task)
        .await
        .expect("read post-effect held TaskRun");
    assert_eq!(held.stream_version(), acknowledgement.stream_version());
    assert_eq!(held.state(), runne_runtime_client::TaskRunState::Cancelling);
    assert_ne!(database::local_stop_state(database_path, task), Some(2));
    assert_eq!(database::result_count(database_path, task), 0);
    if std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref()
        == Ok("cancel-restart-after-create-effect")
    {
        restart_cancelled_after_effect(
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
            database_path,
            task,
            create_watch,
        )
        .await;
        return;
    }
    barriers::release("after-exit");
    let state = barriers::wait_audit_only(client, task, database_path, runtime_root).await;
    assert_eq!(
        count_watch_mask(create_watch, libc::IN_CREATE),
        0,
        "create was not repeated after cancellation"
    );
    assert!(
        created.is_file(),
        "completed create effect is not rolled back"
    );
    assert_eq!(
        std::fs::read(created).expect("read retained created content"),
        b"created through approved tool\n"
    );
    assert_eq!(database::result_count(database_path, task), 0);
    assert_eq!(database::local_stop_state(database_path, task), Some(2));
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert!(matches!(
        state,
        runne_runtime_client::TaskRunState::Cancelling
            | runne_runtime_client::TaskRunState::Cancelled
    ));
    assert_eq!(
        barriers::wait_cancelled(client, task, database_path, runtime_root).await,
        runne_runtime_client::TaskRunState::Cancelled,
        "post-create cancellation must not continue: {}",
        diagnostic(database_path, task, runtime_root)
    );
}

async fn restart_cancelled_after_effect(
    active: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    bus: &std::path::Path,
    root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    watch: &std::fs::File,
) {
    let pid = active.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    active
        .test_wait_for_exit(std::time::Duration::from_secs(10))
        .expect("reap daemon after durable cancellation and create effect");
    let (mut reopened, client) =
        super::super::positive::restart_same_root(executable, bus, root).await;
    assert_eq!(
        barriers::wait_cancelled(&client, task, database, root).await,
        runne_runtime_client::TaskRunState::Cancelled
    );
    assert_recovered_cancel(database, root, task, watch);
    let stable = client
        .get_task_run(task)
        .await
        .expect("read recovered cancel");
    let pid = reopened.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    reopened
        .test_wait_for_exit(std::time::Duration::from_secs(10))
        .expect("reap first cancellation reopen");
    let (mut second, second_client) =
        super::super::positive::restart_same_root(executable, bus, root).await;
    let again = second_client
        .get_task_run(task)
        .await
        .expect("read second cancellation reopen");
    assert_eq!(again.state(), runne_runtime_client::TaskRunState::Cancelled);
    assert_eq!(again.stream_version(), stable.stream_version());
    assert_recovered_cancel(database, root, task, watch);
    second.stop().expect("stop second cancellation reopen");
    eprintln!("PASS: D2 cancelled create stayed exactly once across two daemon reopens");
}

fn assert_recovered_cancel(
    database_path: &std::path::Path,
    runtime_root: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    watch: &std::fs::File,
) {
    assert_eq!(database::result_count(database_path, task), 0);
    assert_eq!(database::release_intent_count(database_path, task), 1);
    assert_eq!(database::local_stop_state(database_path, task), Some(2));
    assert_eq!(
        database::invocation_state(database_path, task),
        "uncertain",
        "crash before helper receipt cannot synthesize audit-only bytes"
    );
    assert_eq!(count_watch_mask(watch, libc::IN_CREATE), 0);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
}

async fn cancel(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    version: u64,
    stage: &str,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::TaskRunCancellationAcknowledgement {
    let started = tokio::time::Instant::now();
    client
        .cancel_task_run(runne_runtime_client::CancelTaskRunRequest::new(
            runne_runtime_client::CommandIdentity::new(
                runne_runtime_client::CanonicalId::now_v7(),
                format!("d2-cancel-{stage}-{}", uuid::Uuid::now_v7()),
            )
            .expect("D2 cancel identity"),
            task,
            version,
        ))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "durable cancel {stage} failed after {}ms: {error:?}; {}",
                started.elapsed().as_millis(),
                diagnostic(database, task, runtime_root)
            )
        })
}
