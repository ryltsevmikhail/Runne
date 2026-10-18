use super::super::super::diagnostic::fixture_count;
use super::super::verify;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(crate) async fn before_receipt(
    barrier: &str,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
    runtime_root: &std::path::Path,
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    target: &std::path::Path,
    watch: &std::fs::File,
    event_mask: u32,
    expected_events: usize,
    expected_releases: u32,
    expected_contents: Option<&[u8]>,
) {
    wait_for_barrier(barrier).await;
    assert_eq!(
        super::super::diagnostic::count_watch_mask(watch, event_mask),
        expected_events,
        "native filesystem evidence at {barrier}"
    );
    if let Some(contents) = expected_contents {
        assert_eq!(
            std::fs::read(target).expect("read native effect before crash"),
            contents
        );
    }
    assert_eq!(verify::result_count(database, task), 0);
    assert_eq!(
        verify::release_intent_count(database, task),
        expected_releases
    );
    kill_supervised_daemon(supervisor);

    let (mut reopened, client) =
        restart_same_root(executable, session_bus_socket, runtime_root).await;
    let state = super::super::faults::wait_terminal(&client, task, database, runtime_root).await;
    assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
    super::super::faults::assert_failure_projection(database, task);
    assert_proved_empty_uncertain(database, task);
    assert_eq!(verify::result_count(database, task), 0);
    assert_eq!(
        verify::release_intent_count(database, task),
        expected_releases
    );
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert_eq!(
        super::super::diagnostic::count_watch_mask(watch, event_mask),
        0,
        "first reopen did not repeat the native filesystem effect"
    );
    if let Some(contents) = expected_contents {
        assert_eq!(
            std::fs::read(target).expect("effect remains after crash"),
            contents
        );
    }
    let version = client
        .get_task_run(task)
        .await
        .expect("stable uncertain D2 task");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    recheck_same_failed_head(
        &client,
        &mut reopened,
        task,
        version.stream_version(),
        "first reopen neither retried nor continued the uncertain invocation",
    )
    .await;

    kill_supervised_daemon(&mut reopened);
    let (mut reopened_again, client_again) =
        restart_same_root(executable, session_bus_socket, runtime_root).await;
    let second = client_again
        .get_task_run(task)
        .await
        .expect("second D2 reopen");
    assert_eq!(second.stream_version(), version.stream_version());
    assert_eq!(verify::result_count(database, task), 0);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert_eq!(
        super::super::diagnostic::count_watch_mask(watch, event_mask),
        0,
        "second reopen did not repeat the native filesystem effect"
    );
    assert_eq!(second.state(), runne_runtime_client::TaskRunState::Failed);
    super::super::faults::assert_failure_projection(database, task);
    assert_proved_empty_uncertain(database, task);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    recheck_same_failed_head(
        &client_again,
        &mut reopened_again,
        task,
        version.stream_version(),
        "second reopen did not duplicate progress",
    )
    .await;
    reopened_again.stop().expect("stop second D2 crash reopen");
}

async fn recheck_same_failed_head(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    task: runne_runtime_client::CanonicalId,
    expected_version: u64,
    assertion: &str,
) {
    use runne_runtime_client::RuntimeApiErrorKind;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut transport_unavailable = 0u32;
    loop {
        let response = tokio::time::timeout_at(deadline, client.get_task_run(task))
            .await
            .unwrap_or_else(|_| {
                let status = supervisor
                    .test_wait_for_exit(std::time::Duration::ZERO)
                    .expect("poll exact owned daemon after same-head GET deadline");
                panic!("same-head GET exceeded 5-second deadline; owned daemon status={status:?}");
            });
        match response {
            Ok(snapshot) => {
                assert_eq!(snapshot.state(), runne_runtime_client::TaskRunState::Failed);
                assert_eq!(snapshot.stream_version(), expected_version, "{assertion}");
                if transport_unavailable > 0 {
                    eprintln!(
                        "INFO: same-head read recovered after {transport_unavailable} read-only transport-unavailable response(s)"
                    );
                }
                return;
            }
            Err(error)
                if error.kind() == RuntimeApiErrorKind::Unavailable
                    && error.request_id().is_none() =>
            {
                transport_unavailable = transport_unavailable.saturating_add(1);
                let status = supervisor
                    .test_wait_for_exit(std::time::Duration::ZERO)
                    .expect("poll exact owned daemon after transport-unavailable GET");
                assert_eq!(
                    status,
                    runne_platform_desktop::BundledRuntimeProcessStatus::Running,
                    "daemon process exited during read-only same-head check"
                );
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "same-head GET remained transport-unavailable for 5 seconds while the owned daemon stayed running"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(error) => panic!(
                "same-head GET failed with non-retryable runtime API error: kind={:?}, request_id={:?}",
                error.kind(),
                error.request_id()
            ),
        }
    }
}

fn assert_proved_empty_uncertain(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) {
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only uncertain D2 invocation view");
    let row: (String, bool, bool, i64, bool) = db
        .query_row(
            "SELECT state,helper_receipt_bytes IS NULL,result_bytes IS NULL,local_stop_state,managed_area_identity=empty_proof_identity AND empty_proof_identity IS NOT NULL FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .expect("read exact unknown-outcome invocation proof");
    assert_eq!(
        row.0, "uncertain",
        "no persisted receipt means no audit-only state"
    );
    assert!(row.1, "no provider/helper audit bytes were fabricated");
    assert!(
        row.2,
        "unknown outcome remains distinct from a durable Result"
    );
    assert_eq!(row.3, 2, "local managed area has ProvedEmpty stop");
    assert!(row.4, "empty proof is bound to the exact managed area");
}

pub(super) fn kill_supervised_daemon(
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
) {
    let child = supervisor.test_owned_child_id() as libc::pid_t;
    assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
    supervisor
        .test_wait_for_exit(std::time::Duration::from_secs(10))
        .expect("reap exact D2 daemon after crash barrier");
}

pub(crate) async fn restart_same_root(
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
    runtime_root: &std::path::Path,
) -> (
    runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    runne_runtime_client::AuthenticatedRuntimeClient,
) {
    let spec =
        runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(executable, runtime_root)
            .expect("same-root D2 restart spec")
            .with_openai_provider_activation()
            .with_validated_session_bus_address(session_bus_socket)
            .expect("same fixture session bus");
    let mut reopened = runne_platform_desktop::ProtectedBundledRuntimeSupervisor::new(
        runne_platform_desktop::DevelopmentBundledRuntimeLauncher::new(),
        spec,
    );
    let start = if crate::t1_credential_companion::enabled() {
        reopened.start_capturing_for_test(crate::random_secret())
    } else {
        reopened.start()
    };
    start.unwrap_or_else(|error| {
        let stage = std::fs::read_to_string(runtime_root.join(".runne-test-protected-d2-stage"))
            .unwrap_or_else(|_| "unavailable".to_owned());
        panic!("restart same D2 runtime root failed at fixture stage {stage}: {error}");
    });
    let client = reopened
        .take_runtime_profile()
        .expect("restarted D2 profile")
        .connect(std::time::Duration::from_secs(10))
        .await
        .expect("connect same-root D2 restart");
    reopened
        .record_client_ready(&client)
        .expect("record exact restarted D2 readiness");
    (reopened, client)
}

pub(super) async fn wait_for_barrier(name: &str) {
    let directory = std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("fixture barrier directory");
    let entered = directory.join(format!("{name}.entered"));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while !entered.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name} barrier never reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
