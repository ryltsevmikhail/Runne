use super::CommittedModeSelection;
use runne_domain::task_run::TaskRunEvent;
use runne_store::codec::{StoreCodec, TaskRunEventCodec};

pub(in crate::t1_positive::d2_pending) fn active_downgrade_barrier() -> Option<&'static str> {
    if !matches!(
        std::env::var("RUNNE_TEST_D2_PERMISSION_MODE").as_deref(),
        Ok("full_access")
    ) {
        return None;
    }
    let scenario = std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").ok();
    let barrier = std::env::var("RUNNE_TEST_LOCAL_WORKER_BARRIER").ok();
    match (scenario.as_deref(), barrier.as_deref()) {
        (Some("crash-before-go"), Some("pre-release")) => Some("pre-release"),
        (Some("crash-after-create-effect"), Some("after-exit")) => Some("after-exit"),
        (Some("crash-after-create-effect"), Some("after-result-before-step-outcome")) => {
            Some("after-result-before-step-outcome")
        }
        (Some("crash-after-create-effect"), Some("after-terminal")) => Some("after-terminal"),
        _ => None,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture keeps the exact task, managed effect, authority, barrier, and reopen handles together."
)]
pub(in crate::t1_positive::d2_pending) async fn exercise_active_downgrade(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    task: runne_runtime_client::CanonicalId,
    created: &std::path::Path,
    create_watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    let barrier = active_downgrade_barrier().expect("active typed downgrade fixture");
    wait_entered(barrier).await;
    match barrier {
        "pre-release" => {
            assert!(!created.exists(), "create is held before helper GO");
            assert_eq!(
                super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
                0
            );
            assert_eq!(super::super::verify::result_count(database, task), 0);
            assert_eq!(
                super::super::verify::release_intent_count(database, task),
                0
            );
        }
        "after-exit" => assert_single_create(created, create_watch),
        "after-result-before-step-outcome" => {
            assert_single_create(created, create_watch);
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 0);
        }
        "after-terminal" => {
            assert_single_create(created, create_watch);
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 1);
            assert_eq!(provider_round_count(database, task), 1);
        }
        _ => unreachable!("barrier was matched above"),
    }

    let selection = commit_ask_always(client, workspace_id, supervisor).await;
    release(barrier);
    let terminal = super::super::verify::wait_success(client, task, database, runtime_root).await;
    assert_ne!(
        terminal.state(),
        runne_runtime_client::TaskRunState::Succeeded,
        "downgrade fenced stale broad-mode continuation"
    );
    let stream_version = terminal.stream_version();
    assert_step_outcome_count(
        database,
        task,
        if barrier == "after-terminal" { 1 } else { 0 },
    );
    assert_eq!(
        super::super::super::diagnostic::fixture_count(
            runtime_root,
            "fixture-provider-request-count"
        ),
        1,
        "downgrade did not dispatch a continuation"
    );
    assert_eq!(provider_round_count(database, task), 1);
    match barrier {
        "pre-release" => {
            assert!(!created.exists());
            assert_eq!(super::super::verify::result_count(database, task), 0);
            assert_eq!(
                super::super::verify::release_intent_count(database, task),
                0
            );
        }
        "after-exit" => assert_encrypted_audit(database, task),
        "after-result-before-step-outcome" => {
            super::super::verify::assert_encrypted_results(database, task, 1);
        }
        "after-terminal" => {
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 1);
        }
        _ => unreachable!("barrier was matched above"),
    }
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );

    supervisor
        .stop()
        .expect("stop daemon before typed-mode Store reopen");
    let (mut reopened, reopened_client) =
        super::super::crash::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let status = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read downgraded mode after Store reopen");
    assert_eq!(status.selected_mode, runne_api::PermissionModeV1::AskAlways);
    assert_eq!(status.authorization_revision, selection.revision);
    assert_eq!(
        reopened_client
            .permission_mode_command_status(workspace_id, selection.command_id)
            .await
            .expect("read downgrade receipt after Store reopen"),
        selection.status
    );
    assert_eq!(
        reopened_client
            .request_permission_mode_change(selection.request)
            .await
            .expect("replay downgrade receipt after Store reopen"),
        selection.status
    );
    let reopened_task = reopened_client
        .get_task_run(task)
        .await
        .expect("read terminal TaskRun after Store reopen");
    assert_eq!(reopened_task.state(), terminal.state());
    assert_eq!(reopened_task.stream_version(), stream_version);
    assert_step_outcome_count(
        database,
        task,
        if barrier == "after-terminal" { 1 } else { 0 },
    );
    assert_eq!(
        super::super::super::diagnostic::fixture_count(
            runtime_root,
            "fixture-provider-request-count"
        ),
        1,
        "reopen did not dispatch a continuation"
    );
    assert_eq!(provider_round_count(database, task), 1);
    match barrier {
        "pre-release" => assert!(!created.exists()),
        "after-exit" => {
            assert_create_preserved(created);
            assert_encrypted_audit(database, task);
        }
        "after-result-before-step-outcome" => {
            assert_create_preserved(created);
            super::super::verify::assert_encrypted_results(database, task, 1);
        }
        "after-terminal" => {
            assert_create_preserved(created);
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 1);
        }
        _ => unreachable!("barrier was matched above"),
    }
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );
    reopened.stop().expect("stop reopened typed-mode runtime");
    eprintln!("PASS: typed create downgrade at {barrier} remained fenced across Store reopen");
}

async fn commit_ask_always(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
) -> CommittedModeSelection {
    let before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Full Access mode before downgrade");
    assert_eq!(
        before.selected_mode,
        runne_api::PermissionModeV1::FullAccess
    );
    let (command_id, request) = super::mode_request(
        workspace_id,
        before.authorization_revision,
        runne_api::PermissionModeV1::AskAlways,
    );
    let pending = client.request_permission_mode_change(request.clone()).await;
    super::require_pending_or_readback(client, workspace_id, command_id, pending).await;
    super::commit_current_pending(client, supervisor, command_id).await;
    let status = client
        .permission_mode_command_status(workspace_id, command_id)
        .await
        .expect("read canonical Ask Always downgrade receipt");
    let runne_api::PermissionModeCommandStatusV2::Committed { receipt } = &status else {
        panic!("native confirmation did not commit typed downgrade");
    };
    assert_eq!(
        receipt.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(
        receipt.authorization_revision,
        before.authorization_revision + 1
    );
    let revision = receipt.authorization_revision;
    CommittedModeSelection {
        mode: runne_api::PermissionModeV1::AskAlways,
        command_id,
        request,
        status,
        revision,
    }
}

fn assert_single_create(created: &std::path::Path, watch: &std::fs::File) {
    assert!(created.is_file(), "create_new had a real Linux file effect");
    assert_eq!(
        std::fs::read(created).expect("read actual typed create result"),
        super::super::CREATE_BYTES
    );
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(watch, libc::IN_CREATE),
        1,
        "typed create produced exactly one Linux IN_CREATE"
    );
}

fn assert_create_preserved(created: &std::path::Path) {
    assert!(
        created.is_file(),
        "completed create remains after Store reopen"
    );
    assert_eq!(
        std::fs::read(created).expect("read retained typed create result"),
        super::super::CREATE_BYTES
    );
}

fn assert_encrypted_audit(database: &std::path::Path, task: runne_runtime_client::CanonicalId) {
    assert_eq!(super::super::verify::invocation_count(database, task), 1);
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only typed audit view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("typed TaskRun UUID")
        .into_bytes();
    let row: (String, usize, usize, usize, usize, bool, i64, bool) = db
        .query_row(
            "SELECT state,length(canonical_arguments),args_plaintext_len,length(helper_receipt_bytes),receipt_plaintext_len,result_bytes IS NULL,local_stop_state,managed_area_identity=empty_proof_identity AND empty_proof_identity IS NOT NULL FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
        )
        .expect("read exact typed audit receipt metadata");
    assert_eq!(row.0, "audit_only");
    assert_eq!(row.1, row.2 + 16, "tool arguments remain encrypted");
    assert_eq!(row.3, row.4 + 16, "helper evidence remains encrypted");
    assert!(row.5, "audit evidence cannot feed a tool result");
    assert_eq!(row.6, 2, "managed effect area has an empty stop proof");
    assert!(row.7, "stop proof is bound to the exact managed area");
    assert_eq!(super::super::verify::result_count(database, task), 0);
}

fn assert_step_outcome_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
    expected: usize,
) {
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only pre-continuation TaskRun view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("typed TaskRun UUID")
        .into_bytes();
    let payloads = db
        .prepare("SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1")
        .expect("prepare TaskRun outcome scan")
        .query_map([task_bytes.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .expect("query TaskRun events")
        .collect::<Result<Vec<_>, _>>()
        .expect("read TaskRun events");
    let actual = payloads
        .iter()
        .filter(|payload| {
            matches!(
                TaskRunEventCodec.decode(payload),
                Ok(TaskRunEvent::StepOutcomeRecorded { .. })
            )
        })
        .count();
    assert_eq!(actual, expected, "typed TaskRun step-outcome count");
}

fn provider_round_count(
    database: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) -> i64 {
    let db =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only provider-round view");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("typed TaskRun UUID")
        .into_bytes();
    db.query_row(
        "SELECT count(*) FROM taskrun_provider_round_bindings WHERE taskrun_id=?1",
        [task_bytes.as_slice()],
        |row| row.get(0),
    )
    .expect("read durable provider-round count")
}

async fn wait_entered(name: &str) {
    let directory = barrier_dir();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    while !directory.join(format!("{name}.entered")).is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "typed barrier {name} not reached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn release(name: &str) {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(barrier_dir().join(format!("{name}.release")))
        .expect("release exact typed barrier once");
}

fn barrier_dir() -> std::path::PathBuf {
    std::env::var_os("RUNNE_TEST_LOCAL_WORKER_BARRIER_DIR")
        .map(std::path::PathBuf::from)
        .expect("parent supplied typed barrier directory")
}
