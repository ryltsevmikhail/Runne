use super::diagnostic::{diagnostic, open_watch, read_watch};
use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The pending-crash fixture keeps its exact runtime and reopen handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &std::path::Path,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    let target = project_directory.join("fixture-read.txt");
    std::fs::write(&target, b"approved fixture bytes\n").expect("seed D2 read target");
    let watch = open_watch(&target);
    let text = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .expect("pinned base profile");
    let tools = runne_provider_openai::OpenAiResponsesToolProfile::new(text)
        .expect("fixed Linux tool profile");
    let selected = runne_api::SelectedProviderProfile::new(
        runne_provider_openai::OPENAI_RESPONSES_TOOL_PROFILE_ID.to_owned(),
        tools.profile_digest(),
    )
    .expect("selected exact tool profile");
    let id = runne_runtime_client::CanonicalId::now_v7();
    let request = runne_runtime_client::SubmitTaskRunRequest::new(
        runne_runtime_client::CommandIdentity::new(id, format!("d2-pending-{id}"))
            .expect("D2 submit identity"),
        conversation_id,
        workspace_id,
        if matches!(
            std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref(),
            Ok("crash-pending-approval"
                | "restart-started-before-cycle"
                | "restart-cycle-before-budget"
                | "restart-context-committed"
                | "restart-cancelled-before-budget"
                | "restart-plan-committed"
                | "restart-proposal-before-invocation"
                | "restart-dispatched-remote-unknown")
        ) {
            "Read fixture-read.txt and create fixture-created.txt with the approved bytes."
        } else {
            "Read fixture-read.txt through the workspace file read tool."
        },
    )
    .expect("D2 prompt")
    .with_selected_profile(selected)
    .expect("exact selected tool profile");
    let task = client
        .submit_task_run(request)
        .await
        .expect("submit explicit mock D2 TaskRun")
        .task_run_id();
    let restart_stage = match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
        Ok("restart-started-before-cycle") => Some("start_cycle"),
        Ok("restart-cycle-before-budget") => Some("cycle_started"),
        Ok("restart-context-committed") => Some("context_committed"),
        Ok("restart-cancelled-before-budget") => Some("cycle_started"),
        Ok("restart-plan-committed") => Some("plan_committed"),
        Ok("restart-proposal-before-invocation") => Some("proposal_received"),
        Ok("restart-dispatched-remote-unknown") => Some("provider_uncertain"),
        _ => None,
    };
    if let Some(stage) = restart_stage {
        super::positive::crash::at_restart_stage(
            stage,
            client,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
            database,
            task,
            conversation_id,
            &target,
            &watch,
            std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref()
                == Ok("restart-cancelled-before-budget"),
        )
        .await;
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
    let approval = loop {
        if let Some(approval) = client
            .list_pending_approvals()
            .await
            .expect("list human approvals")
            .into_iter()
            .find(|approval| approval.task_run_id() == task)
        {
            break approval;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 proposal never became Pending; {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(approval.requires_decision());
    assert_eq!(
        read_watch(&watch),
        0,
        "Pending proposal must not open target for reading"
    );
    eprintln!(
        "RUN: D2 pending task={} invocation={} approval={} effect_count=0 target_open_events=0",
        task,
        approval.invocation_id(),
        approval.approval_id()
    );
    if std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() == Ok("crash-pending-approval") {
        super::positive::crash::before_unlaunched(
            None,
            "proposed",
            1,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
            database,
            task,
            &target,
            &watch,
        )
        .await;
        return;
    }
    assert_eq!(std::fs::read(&target).unwrap(), b"approved fixture bytes\n");
    let task_bytes = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open daemon SQLite read-only view");
    let (state, payload_len, args_len, area_state, released, result_present):
        (String, usize, usize, i64, bool, bool) = connection
        .query_row(
            "SELECT state, length(canonical_arguments), args_plaintext_len, local_stop_state, release_started, result_digest IS NOT NULL FROM taskrun_tool_invocations WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .expect("read durable tool proposal row");
    assert_eq!(state, "proposed");
    assert_eq!(
        payload_len,
        args_len + 16,
        "arguments are stored as ciphertext with the AEAD tag"
    );
    assert_eq!(
        area_state, 0,
        "Pending approval precedes managed-area creation"
    );
    assert!(!released, "Pending approval precedes native GO");
    assert!(!result_present, "Pending approval precedes tool execution");
    let effects_used: u32 = connection
        .query_row(
            "SELECT effects_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("read canonical effect budget");
    assert_eq!(effects_used, 0);

    eprintln!(
        "RUN: D2 pending task={} invocation={} approval={} effect_count=0 target_open_events=0",
        task,
        approval.invocation_id(),
        approval.approval_id()
    );
    assert_eq!(
        std::fs::read(&target).expect("read pending target"),
        b"approved fixture bytes\n"
    );
}
