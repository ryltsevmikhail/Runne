use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct DowngradeReceiptFacts {
    attempt_state: String,
    attempt_id: Vec<u8>,
    attempt_fence: i64,
    stop_count: i64,
    stop_reason: i64,
    stop_attempt_id: Vec<u8>,
    terminal_count: i64,
    terminal_attempt_id: Vec<u8>,
    terminal_fence: i64,
    terminal_kind: i64,
    terminal_event_id: Vec<u8>,
    terminal_version: i64,
    receipt_count: i64,
    receipt_attempt_id: Vec<u8>,
    receipt_fence: i64,
    receipt_event_id: Vec<u8>,
    receipt_version: i64,
    event_id: Vec<u8>,
    event_aggregate_type: i64,
    event_aggregate_id: Vec<u8>,
    event_sequence: i64,
}

type LocalEffectFacts = (
    runne_runtime_client::LocalExecutionOutcome,
    runne_runtime_client::LocalStopEvidence,
    Option<i32>,
);

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture needs the exact runtime root, public client, and same-root restart handles."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
) {
    eprintln!("RUN: Full Access live downgrade with the fixture's explicit mock native authority");
    let initial_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read exact Full Access selection before live downgrade");
    assert_eq!(
        initial_mode.selected_mode,
        runne_api::PermissionModeV1::FullAccess
    );

    let listener = LoopbackCapture::new();
    let tag = format!("local-live-downgrade-{}", uuid::Uuid::now_v7());
    let started = project_directory.join(format!("{tag}-started"));
    let gate = project_directory.join(format!("{tag}-gate"));
    let late = project_directory.join(format!("{tag}-late"));
    let script = format!(
        "printf 'started\\n' >> {}; while [ ! -e {} ]; do sleep 0.02; done; printf 'late\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'late\\n' >&3; exec 3>&-",
        shell_quote_path(&started),
        shell_quote_path(&gate),
        shell_quote_path(&late),
        listener.port
    );
    let request = local_submit(conversation_id, workspace_id, &tag, &script);
    let task = client
        .submit_task_run(request.clone())
        .await
        .expect("submit one Full Access local command at its captured revision")
        .task_run_id();
    wait_for_file(&started).await;
    assert_eq!(
        std::fs::read_to_string(&started).expect("read started marker before downgrade"),
        "started\n",
        "the child appended its one started marker before permission changed"
    );
    assert!(!gate.exists() && !late.exists());
    assert_no_task_approval(client, task).await;

    let next_revision = super::super::super::t1_local_only::change_local_permission_mode(
        client,
        workspace_id,
        supervisor,
        runne_api::PermissionModeV1::AskAlways,
    )
    .await;
    assert_eq!(next_revision, initial_mode.authorization_revision + 1);
    let downgraded_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Ask Always selection after live downgrade");
    assert_eq!(
        downgraded_mode.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(downgraded_mode.authorization_revision, next_revision);

    let terminal = wait_for_terminal(client, database, task, &started, &late).await;
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read public live-downgrade process effect");
    let local = effects
        .local_command()
        .expect("public live-downgrade local-command effect");
    let local_facts = (local.outcome(), local.stop(), local.exit_code());
    assert_eq!(
        local_facts.0,
        runne_runtime_client::LocalExecutionOutcome::Exited
    );
    assert_eq!(
        local_facts.1,
        runne_runtime_client::LocalStopEvidence::Confirmed
    );
    let receipt = read_downgrade_receipt(database, task);
    assert_downgrade_receipt(&receipt, task);
    assert_no_task_approval(client, task).await;

    // The fixture releases the child only after its stop is publicly confirmed.
    std::fs::write(&gate, "release after confirmed stop\n").expect("release stopped child gate");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_started_once(&started);
    assert!(
        !late.exists(),
        "confirmed stop prevents the gated late write"
    );

    assert_replay_is_inert(
        client,
        database,
        &request,
        task,
        &terminal,
        local_facts,
        &receipt,
        &started,
        &late,
    )
    .await;

    supervisor
        .stop()
        .expect("gracefully stop exact live-downgrade runtime before same-root reopen");
    let (mut reopened, reopened_client) = super::super::super::t1_positive::restart_same_root(
        executable,
        session_bus_socket,
        runtime_root,
    )
    .await;
    let reopened_mode = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read persisted Ask Always selection after same-root reopen");
    assert_eq!(
        reopened_mode.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(reopened_mode.authorization_revision, next_revision);
    assert_replay_is_inert(
        &reopened_client,
        database,
        &request,
        task,
        &terminal,
        local_facts,
        &receipt,
        &started,
        &late,
    )
    .await;

    // Restart replaces process-local protected root handles; rebind this same
    // already-selected project root before asking for a new local approval.
    let workspace = reopened_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace before same-root admission refresh");
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        uuid::Uuid::parse_str(&workspace_id.to_string())
            .expect("workspace UUID")
            .into_bytes(),
    );
    let root = runne_platform_desktop::VerifiedRootHandle::open(project_directory)
        .expect("reopen the existing rebound project root handle");
    let admission = reopened
        .prepare_root_admission(&root, workspace_api_id, workspace.version())
        .expect("prepare fresh admission for the existing project root");
    let admission = runne_runtime_client::ProtectedRootAdmission::from_verified(admission)
        .expect("wrap fresh protected root admission");
    let bind_id = runne_runtime_client::CanonicalId::now_v7();
    let bind_identity = runne_runtime_client::CommandIdentity::new(
        bind_id,
        format!("t1-live-downgrade-root-rebind-{bind_id}"),
    )
    .expect("fresh root-rebind command identity");
    reopened_client
        .bind_workspace_root(
            runne_runtime_client::BindWorkspaceRootRequest::new(
                bind_identity,
                workspace_id,
                workspace.version(),
                &admission,
            )
            .expect("same-project root-rebind request"),
        )
        .await
        .expect("bind the existing project root to fresh process admission");
    let rebound_workspace = reopened_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace after same-project root rebind");
    let trust = super::super::super::t1_trust_control::grant_through_public_control(
        &reopened_client,
        rebound_workspace.project_id(),
        workspace_id,
    )
    .await;
    assert_eq!(
        trust.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted
    );
    let mode_after_rebind = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Ask Always selection after root rebind");
    assert_eq!(
        mode_after_rebind.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(mode_after_rebind.authorization_revision, next_revision);

    let stale_tag = format!("local-live-downgrade-stale-{}", uuid::Uuid::now_v7());
    let stale_started = project_directory.join(format!("{stale_tag}-started"));
    let stale_late = project_directory.join(format!("{stale_tag}-late"));
    let stale_script = format!(
        "printf 'unexpected-start\\n' >> {}; printf 'late\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'ask\\n' >&3; exec 3>&-",
        shell_quote_path(&stale_started),
        shell_quote_path(&stale_late),
        listener.port
    );
    let stale_request = local_submit(conversation_id, workspace_id, &stale_tag, &stale_script);
    let stale_task = reopened_client
        .submit_task_run(stale_request.clone())
        .await
        .expect("submit the distinct stale-selection local command")
        .task_run_id();
    let stale_terminal = wait_for_terminal(
        &reopened_client,
        database,
        stale_task,
        &stale_started,
        &stale_late,
    )
    .await;
    assert_eq!(
        super::super::super::t1_startup_diagnostic::local_preapproval_diagnostic(runtime_root),
        "current_managed_identity_mismatch",
        "the stale managed identity was rejected before local permission capture"
    );
    assert_stale_selection_failed(
        &reopened_client,
        database,
        stale_task,
        &stale_terminal,
        &stale_started,
        &stale_late,
    )
    .await;
    assert_stale_request_replay_is_inert(
        &reopened_client,
        database,
        &stale_request,
        stale_task,
        &stale_terminal,
        &stale_started,
        &stale_late,
    )
    .await;

    reopened
        .stop()
        .expect("stop after stale-selection settlement and pre-reopen replay");
    let (mut reopened_again, reopened_again_client) =
        super::super::super::t1_positive::restart_same_root(
            executable,
            session_bus_socket,
            runtime_root,
        )
        .await;
    let mode_after_second_reopen = reopened_again_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read persisted Ask Always after second same-root reopen");
    assert_eq!(
        mode_after_second_reopen.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(
        mode_after_second_reopen.authorization_revision,
        next_revision
    );

    let workspace = reopened_again_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace before second same-root admission refresh");
    let workspace_api_id = runne_api::WorkspaceId::from_bytes(
        uuid::Uuid::parse_str(&workspace_id.to_string())
            .expect("workspace UUID")
            .into_bytes(),
    );
    let root = runne_platform_desktop::VerifiedRootHandle::open(project_directory)
        .expect("reopen the existing rebound project root handle");
    let admission = reopened_again
        .prepare_root_admission(&root, workspace_api_id, workspace.version())
        .expect("prepare fresh admission for the existing project root after second reopen");
    let admission = runne_runtime_client::ProtectedRootAdmission::from_verified(admission)
        .expect("wrap second-reopen protected root admission");
    let bind_id = runne_runtime_client::CanonicalId::now_v7();
    let bind_identity = runne_runtime_client::CommandIdentity::new(
        bind_id,
        format!("t1-live-downgrade-root-rebind-{bind_id}"),
    )
    .expect("fresh second-reopen root-rebind command identity");
    reopened_again_client
        .bind_workspace_root(
            runne_runtime_client::BindWorkspaceRootRequest::new(
                bind_identity,
                workspace_id,
                workspace.version(),
                &admission,
            )
            .expect("same-project second-reopen root-rebind request"),
        )
        .await
        .expect("bind the existing project root to second process admission");
    let rebound_workspace = reopened_again_client
        .get_workspace(workspace_id)
        .await
        .expect("read workspace after second same-project root rebind");
    let trust = super::super::super::t1_trust_control::grant_through_public_control(
        &reopened_again_client,
        rebound_workspace.project_id(),
        workspace_id,
    )
    .await;
    assert_eq!(
        trust.status(),
        runne_runtime_client::ProjectTrustStatusDto::Trusted
    );
    let mode_after_second_rebind = reopened_again_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read persisted Ask Always after second root rebind");
    assert_eq!(
        mode_after_second_rebind.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(
        mode_after_second_rebind.authorization_revision,
        next_revision
    );

    assert_stale_request_replay_is_inert(
        &reopened_again_client,
        database,
        &stale_request,
        stale_task,
        &stale_terminal,
        &stale_started,
        &stale_late,
    )
    .await;

    let fresh_revision = super::super::super::t1_local_only::change_local_permission_mode(
        &reopened_again_client,
        workspace_id,
        &mut reopened_again,
        runne_api::PermissionModeV1::AskAlways,
    )
    .await;
    assert_eq!(fresh_revision, next_revision + 1);
    let refreshed_mode = reopened_again_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read refreshed Ask Always selection before fresh approval");
    assert_eq!(
        refreshed_mode.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(refreshed_mode.authorization_revision, fresh_revision);

    let fresh_tag = format!("local-live-downgrade-fresh-{}", uuid::Uuid::now_v7());
    let fresh_started = project_directory.join(format!("{fresh_tag}-started"));
    let fresh_late = project_directory.join(format!("{fresh_tag}-late"));
    let fresh_script = format!(
        "printf 'unexpected-start\\n' >> {}; printf 'late\\n' >> {}; exec 3<>/dev/tcp/127.0.0.1/{}; printf 'ask\\n' >&3; exec 3>&-",
        shell_quote_path(&fresh_started),
        shell_quote_path(&fresh_late),
        listener.port
    );
    let fresh_request = local_submit(conversation_id, workspace_id, &fresh_tag, &fresh_script);
    let fresh_task = reopened_again_client
        .submit_task_run(fresh_request)
        .await
        .expect("submit a distinct refreshed Ask Always local command")
        .task_run_id();
    let approval = super::wait_for_approval(&reopened_again_client, fresh_task).await;
    assert_eq!(approval.task_run_id(), fresh_task);
    assert_eq!(approval.action(), "local_command.execute");
    assert!(
        !fresh_started.exists() && !fresh_late.exists(),
        "the distinct Ask Always command has no effect while its exact approval is pending"
    );
    deny_exact(&reopened_again_client, &approval).await;
    let denied = wait_for_terminal(
        &reopened_again_client,
        database,
        fresh_task,
        &fresh_started,
        &fresh_late,
    )
    .await;
    assert_eq!(denied.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(denied.terminal_result(), None);
    let denied_effects = reopened_again_client
        .get_task_run_effects(fresh_task)
        .await
        .expect("read denied refreshed Ask Always effects");
    let denied_local = denied_effects
        .local_command()
        .expect("denied refreshed Ask Always local-command outcome");
    assert_eq!(
        denied_local.outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        super::local_no_effect_release_facts(database, fresh_task)
            .expect("read-only exact denied no-effect settlement"),
        ("no_effect_terminal".to_owned(), true, 1, 1, 0, 0)
    );
    assert!(
        !fresh_started.exists() && !fresh_late.exists(),
        "denial leaves both separate fresh-task markers absent"
    );
    assert_no_task_approval(&reopened_again_client, fresh_task).await;
    let reopened_denied = reopened_again_client
        .get_task_run(fresh_task)
        .await
        .expect("read denied refreshed Ask Always terminal after cleanup");
    assert_eq!(reopened_denied.stream_version(), denied.stream_version());
    assert_eq!(reopened_denied.terminal_result(), denied.terminal_result());
    assert_started_once(&started);
    assert!(!late.exists());
    assert!(!stale_started.exists() && !stale_late.exists());

    reopened_again
        .stop()
        .expect("stop same-root runtime after live-downgrade cleanup");
    assert!(
        listener.finish().is_empty(),
        "the live listener accepted no connections; it does not observe packet delivery"
    );
}

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture compares the exact request, terminal, local effect, receipt, and effect markers."
)]
async fn assert_replay_is_inert(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    request: &runne_runtime_client::SubmitTaskRunRequest,
    task: runne_runtime_client::CanonicalId,
    expected: &runne_runtime_client::TaskRunSnapshot,
    expected_local: LocalEffectFacts,
    expected_receipt: &DowngradeReceiptFacts,
    started: &Path,
    late: &Path,
) {
    let replay = client
        .submit_task_run(request.clone())
        .await
        .expect("replay the exact retained live-downgrade request");
    assert_eq!(replay.task_run_id(), task);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reread = client
        .get_task_run(task)
        .await
        .expect("read retained live-downgrade terminal after request replay");
    assert_eq!(reread.state(), expected.state());
    assert_eq!(reread.stream_version(), expected.stream_version());
    assert_eq!(reread.terminal_result(), expected.terminal_result());
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read retained public process effects after request replay");
    let local = effects
        .local_command()
        .expect("retained public local-command effect");
    assert_eq!(
        (local.outcome(), local.stop(), local.exit_code()),
        expected_local
    );
    assert_eq!(read_downgrade_receipt(database, task), *expected_receipt);
    assert_started_once(started);
    assert!(!late.exists(), "request replay adds no late file effect");
    assert_no_task_approval(client, task).await;
}

async fn assert_stale_selection_failed(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    task: runne_runtime_client::CanonicalId,
    terminal: &runne_runtime_client::TaskRunSnapshot,
    started: &Path,
    late: &Path,
) {
    assert_eq!(terminal.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(terminal.terminal_result(), None);
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read stale-selection local-command effects");
    assert_eq!(
        effects
            .local_command()
            .expect("stale-selection local-command outcome")
            .outcome(),
        runne_runtime_client::LocalExecutionOutcome::NotStarted
    );
    assert_eq!(
        super::local_no_effect_release_facts(database, task)
            .expect("read exact stale-selection no-effect release and occupation"),
        ("no_effect_terminal".to_owned(), true, 0, 1, 0, 0)
    );
    assert_eq!(
        super::local_precapture_authority_facts(database, task)
            .expect("read absent stale-selection permission authority"),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!(taskrun_claim_count(database, task), 1);
    assert_no_task_approval(client, task).await;
    assert!(!started.exists() && !late.exists());
}

async fn assert_stale_request_replay_is_inert(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    request: &runne_runtime_client::SubmitTaskRunRequest,
    task: runne_runtime_client::CanonicalId,
    terminal: &runne_runtime_client::TaskRunSnapshot,
    started: &Path,
    late: &Path,
) {
    let replay = client
        .submit_task_run(request.clone())
        .await
        .expect("replay the exact stale-selection TaskRun request");
    assert_eq!(replay.task_run_id(), task);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reread = client
        .get_task_run(task)
        .await
        .expect("read stale-selection terminal after exact request replay");
    assert_eq!(reread.state(), terminal.state());
    assert_eq!(reread.stream_version(), terminal.stream_version());
    assert_eq!(reread.terminal_result(), terminal.terminal_result());
    assert_stale_selection_failed(client, database, task, &reread, started, late).await;
}

fn taskrun_claim_count(database: &Path, task: runne_runtime_client::CanonicalId) -> i64 {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open task database read-only for stale claim count");
    let id = uuid::Uuid::parse_str(&task.to_string())
        .expect("stale TaskRun UUID")
        .into_bytes();
    connection
        .query_row(
            "SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1",
            [id.as_slice()],
            |row| row.get(0),
        )
        .expect("read exact stale TaskRun claim count")
}

fn assert_started_once(path: &Path) {
    assert_eq!(
        std::fs::read_to_string(path).expect("read persistent started marker"),
        "started\n",
        "the started effect remains exactly one append"
    );
}

fn read_downgrade_receipt(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> DowngradeReceiptFacts {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open task database read-only for downgrade proof");
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    connection
        .query_row(
            "SELECT a.state,a.attempt_id,a.fence,
                    (SELECT COUNT(*) FROM x2_permission_stop WHERE taskrun_id=a.taskrun_id),
                    s.reason,s.attempt_id,
                    (SELECT COUNT(*) FROM x2_permission_terminal WHERE taskrun_id=a.taskrun_id),
                    t.attempt_id,t.fence,t.terminal_kind,t.event_id,t.terminal_version,
                    (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts
                      WHERE taskrun_id=a.taskrun_id),
                    r.attempt_id,r.fence,r.terminal_event_id,r.terminal_version,
                    e.event_id,e.aggregate_type,e.aggregate_id,e.sequence
               FROM taskrun_local_command_attempts a
               JOIN x2_permission_stop s
                 ON s.taskrun_id=a.taskrun_id AND s.attempt_id=a.attempt_id
               JOIN x2_permission_terminal t
                 ON t.taskrun_id=a.taskrun_id AND t.attempt_id=a.attempt_id
                AND t.fence=a.fence AND t.terminal_kind=1
               JOIN taskrun_terminal_settlement_receipts r
                 ON r.taskrun_id=t.taskrun_id AND r.attempt_id=t.attempt_id
                AND r.fence=t.fence AND r.terminal_event_id=t.event_id
                AND r.terminal_version=t.terminal_version
               JOIN events e
                 ON e.event_id=t.event_id AND e.aggregate_type=1
                AND e.aggregate_id=a.taskrun_id AND e.sequence=t.terminal_version
              WHERE a.taskrun_id=?1 AND s.reason=2",
            [task_id.as_slice()],
            |row| {
                Ok(DowngradeReceiptFacts {
                    attempt_state: row.get(0)?,
                    attempt_id: row.get(1)?,
                    attempt_fence: row.get(2)?,
                    stop_count: row.get(3)?,
                    stop_reason: row.get(4)?,
                    stop_attempt_id: row.get(5)?,
                    terminal_count: row.get(6)?,
                    terminal_attempt_id: row.get(7)?,
                    terminal_fence: row.get(8)?,
                    terminal_kind: row.get(9)?,
                    terminal_event_id: row.get(10)?,
                    terminal_version: row.get(11)?,
                    receipt_count: row.get(12)?,
                    receipt_attempt_id: row.get(13)?,
                    receipt_fence: row.get(14)?,
                    receipt_event_id: row.get(15)?,
                    receipt_version: row.get(16)?,
                    event_id: row.get(17)?,
                    event_aggregate_type: row.get(18)?,
                    event_aggregate_id: row.get(19)?,
                    event_sequence: row.get(20)?,
                })
            },
        )
        .expect("read exact reason-2 stop, attempt, fence, event, and terminal receipt")
}

fn assert_downgrade_receipt(
    facts: &DowngradeReceiptFacts,
    task: runne_runtime_client::CanonicalId,
) {
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    assert_eq!(facts.attempt_state, "cancelled");
    assert_eq!(facts.stop_count, 1);
    assert_eq!(facts.stop_reason, 2);
    assert_eq!(facts.stop_attempt_id, facts.attempt_id);
    assert_eq!(facts.terminal_count, 1);
    assert_eq!(facts.terminal_attempt_id, facts.attempt_id);
    assert_eq!(facts.terminal_fence, facts.attempt_fence);
    assert_eq!(facts.terminal_kind, 1);
    assert_eq!(facts.receipt_count, 1);
    assert_eq!(facts.receipt_attempt_id, facts.attempt_id);
    assert_eq!(facts.receipt_fence, facts.attempt_fence);
    assert_eq!(facts.receipt_event_id, facts.terminal_event_id);
    assert_eq!(facts.receipt_version, facts.terminal_version);
    assert_eq!(facts.event_id, facts.terminal_event_id);
    assert_eq!(facts.event_aggregate_type, 1);
    assert_eq!(facts.event_aggregate_id, task_id);
    assert_eq!(facts.event_sequence, facts.terminal_version);
}
