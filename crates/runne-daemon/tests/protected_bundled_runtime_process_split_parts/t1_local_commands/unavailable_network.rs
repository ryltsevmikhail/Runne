use super::*;
use std::{path::Path, time::Duration};

#[derive(Debug, Eq, PartialEq)]
struct ReceiptFacts {
    claim_count: i64,
    assignment_count: i64,
    attempt_count: i64,
    stop_receipt_count: i64,
    settlement_count: i64,
    attempt_id: Vec<u8>,
    assignment_attempt_id: Vec<u8>,
    settlement_attempt_id: Vec<u8>,
    fence: i64,
    assignment_fence: i64,
    settlement_fence: i64,
    attempt_state: String,
    exit_code: Option<i64>,
    terminal_event_id: Vec<u8>,
    terminal_version: i64,
    event_aggregate_type: i64,
    event_aggregate_id: Vec<u8>,
    event_sequence: i64,
    stream_version: i64,
    stream_last_event_id: Vec<u8>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture carries the real client, supervisor, and same-root restart handles."
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
    let selected = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected Full Access mode before unavailable-network command");
    assert_eq!(
        selected.selected_mode,
        runne_api::PermissionModeV1::FullAccess
    );

    let (held_socket, endpoint) = super::network_matrix::bind_unlistening_tcp();
    let marker = format!("unavailable-network-{}", uuid::Uuid::now_v7());
    let child_path = project_directory.join(format!("{marker}.py"));
    let marker_path = project_directory.join(format!("{marker}.marker"));
    let refusal_path = project_directory.join(format!("{marker}.refusal"));
    let stderr_path = project_directory.join(format!("{marker}.stderr"));
    std::fs::write(&child_path, UNAVAILABLE_NETWORK_CHILD)
        .expect("write fixture-owned unavailable-network child");
    for path in [&marker_path, &refusal_path, &stderr_path] {
        std::fs::write(path, "").expect("prepare unavailable-network evidence file");
    }

    let script = format!(
        "python3 {} 127.0.0.1 {} {} {} {} 2> {}",
        shell_quote(&child_path),
        endpoint.port(),
        shell_quote(&marker_path),
        shell_quote(&refusal_path),
        shell_quote_value(&marker),
        shell_quote(&stderr_path),
    );
    let request = local_submit(conversation_id, workspace_id, &marker, &script);
    let task = client
        .submit_task_run(request.clone())
        .await
        .expect("submit one Full Access unavailable-network local command")
        .task_run_id();
    let terminal = wait_for_terminal(client, database, task, &marker_path, &refusal_path).await;
    assert_eq!(
        terminal.state(),
        runne_runtime_client::TaskRunState::Succeeded
    );
    assert!(matches!(
        terminal.terminal_result(),
        Some(runne_runtime_client::TaskRunTerminalResult::Failure { reason })
            if reason == "local_command_exit_73"
    ));
    assert_eq!(
        std::fs::read_to_string(&marker_path).expect("read one pre-connect marker"),
        format!("{marker}\n")
    );
    assert_eq!(
        std::fs::read_to_string(&refusal_path).expect("read recorded connection refusal"),
        "ECONNREFUSED\n"
    );
    assert!(
        std::fs::read(&stderr_path)
            .expect("read child stderr")
            .is_empty(),
        "expected refusal writes no child diagnostics"
    );
    let local_facts = public_local_facts(client, task).await;
    assert_eq!(
        local_facts,
        (
            runne_runtime_client::LocalExecutionOutcome::Exited,
            runne_runtime_client::LocalStopEvidence::Confirmed,
            Some(73),
        )
    );
    let receipt = read_receipt_facts(database, task);
    assert_receipt_facts(&receipt, task);
    assert_no_task_approval(client, task).await;

    assert_replay_is_inert(
        client,
        database,
        workspace_id,
        selected.authorization_revision,
        &request,
        task,
        &terminal,
        local_facts,
        &receipt,
        &marker_path,
        &refusal_path,
        &stderr_path,
    )
    .await;

    supervisor
        .stop()
        .expect("stop exact Full Access runtime before same-root reopen");
    let (mut reopened, reopened_client) = super::super::super::t1_positive::restart_same_root(
        executable,
        session_bus_socket,
        runtime_root,
    )
    .await;
    assert_replay_is_inert(
        &reopened_client,
        database,
        workspace_id,
        selected.authorization_revision,
        &request,
        task,
        &terminal,
        local_facts,
        &receipt,
        &marker_path,
        &refusal_path,
        &stderr_path,
    )
    .await;
    reopened.stop().expect("stop same-root reopened runtime");
    drop(held_socket);
}

#[path = "unavailable_network/receipts.rs"]
mod receipts;

use receipts::*;
