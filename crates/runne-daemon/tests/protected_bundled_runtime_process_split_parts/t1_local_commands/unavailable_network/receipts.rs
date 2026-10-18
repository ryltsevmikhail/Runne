use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "Compares this fixture's exact replay invariants."
)]
pub(super) async fn assert_replay_is_inert(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    database: &Path,
    workspace_id: runne_runtime_client::CanonicalId,
    authorization_revision: u64,
    request: &runne_runtime_client::SubmitTaskRunRequest,
    task: runne_runtime_client::CanonicalId,
    terminal: &runne_runtime_client::TaskRunSnapshot,
    local_facts: LocalFacts,
    receipt: &ReceiptFacts,
    marker_path: &Path,
    refusal_path: &Path,
    stderr_path: &Path,
) {
    let replay = client
        .submit_task_run(request.clone())
        .await
        .expect("replay exact unavailable-network request");
    assert_eq!(replay.task_run_id(), task);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let reread = client
        .get_task_run(task)
        .await
        .expect("read unavailable-network TaskRun after replay");
    assert_eq!(reread.state(), terminal.state());
    assert_eq!(reread.stream_version(), terminal.stream_version());
    assert_eq!(reread.terminal_result(), terminal.terminal_result());
    assert_eq!(public_local_facts(client, task).await, local_facts);
    assert_eq!(read_receipt_facts(database, task), *receipt);
    let mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Full Access selection after replay");
    assert_eq!(mode.selected_mode, runne_api::PermissionModeV1::FullAccess);
    assert_eq!(mode.authorization_revision, authorization_revision);
    assert_eq!(
        std::fs::read_to_string(marker_path).expect("re-read one child marker"),
        format!("{}\n", marker_path.file_stem().unwrap().to_string_lossy())
    );
    assert_eq!(
        std::fs::read_to_string(refusal_path).expect("re-read one refusal record"),
        "ECONNREFUSED\n"
    );
    assert!(
        std::fs::read(stderr_path)
            .expect("re-read child stderr")
            .is_empty()
    );
    assert_no_task_approval(client, task).await;
}

pub(super) type LocalFacts = (
    runne_runtime_client::LocalExecutionOutcome,
    runne_runtime_client::LocalStopEvidence,
    Option<i32>,
);

pub(super) async fn public_local_facts(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
) -> LocalFacts {
    let effects = client
        .get_task_run_effects(task)
        .await
        .expect("read unavailable-network local effect receipt");
    let local = effects
        .local_command()
        .expect("unavailable-network local command effect");
    (local.outcome(), local.stop(), local.exit_code())
}

pub(super) fn read_receipt_facts(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> ReceiptFacts {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open database read-only for unavailable-network receipt facts");
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_local_command_attempts WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1),
                    (SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1),
                    a.attempt_id,a.fence,x.attempt_id,x.fence,t.attempt_id,t.fence,a.state,a.exit_code,
                    t.terminal_event_id,t.terminal_version,e.aggregate_type,e.aggregate_id,e.sequence,
                    s.current_version,s.last_event_id
               FROM taskrun_local_command_attempts a
               JOIN taskrun_assignments x ON x.taskrun_id=a.taskrun_id
               JOIN taskrun_terminal_settlement_receipts t ON t.taskrun_id=x.taskrun_id
                    AND t.fence=x.fence AND t.attempt_id=x.attempt_id
               JOIN events e ON e.event_id=t.terminal_event_id
               JOIN aggregate_streams s ON s.aggregate_type=e.aggregate_type
                    AND s.aggregate_id=e.aggregate_id
              WHERE a.taskrun_id=?1",
            [task_id.as_slice()],
            |row| {
                Ok(ReceiptFacts {
                    claim_count: row.get(0)?,
                    assignment_count: row.get(1)?,
                    attempt_count: row.get(2)?,
                    stop_receipt_count: row.get(3)?,
                    settlement_count: row.get(4)?,
                    attempt_id: row.get(5)?,
                    assignment_attempt_id: row.get(7)?,
                    settlement_attempt_id: row.get(9)?,
                    fence: row.get(6)?,
                    assignment_fence: row.get(8)?,
                    settlement_fence: row.get(10)?,
                    attempt_state: row.get(11)?,
                    exit_code: row.get(12)?,
                    terminal_event_id: row.get(13)?,
                    terminal_version: row.get(14)?,
                    event_aggregate_type: row.get(15)?,
                    event_aggregate_id: row.get(16)?,
                    event_sequence: row.get(17)?,
                    stream_version: row.get(18)?,
                    stream_last_event_id: row.get(19)?,
                })
            },
        )
        .expect("read exact attempt and terminal settlement receipt facts")
}

pub(super) fn assert_receipt_facts(facts: &ReceiptFacts, task: runne_runtime_client::CanonicalId) {
    let task_id = uuid::Uuid::parse_str(&task.to_string())
        .expect("TaskRun UUID")
        .into_bytes();
    assert_eq!(facts.claim_count, 1);
    assert_eq!(facts.assignment_count, 1);
    assert_eq!(facts.attempt_count, 1);
    assert_eq!(facts.stop_receipt_count, 0);
    assert_eq!(facts.settlement_count, 1);
    assert_eq!(facts.attempt_id, facts.assignment_attempt_id);
    assert_eq!(facts.attempt_id, facts.settlement_attempt_id);
    assert_eq!(facts.fence, facts.assignment_fence);
    assert_eq!(facts.fence, facts.settlement_fence);
    assert_eq!(facts.attempt_state, "completed");
    assert_eq!(facts.exit_code, Some(73));
    assert_eq!(facts.event_aggregate_type, 1);
    assert_eq!(facts.event_aggregate_id, task_id);
    assert_eq!(facts.event_sequence, facts.terminal_version);
    assert_eq!(facts.stream_version, facts.terminal_version);
    assert_eq!(facts.stream_last_event_id, facts.terminal_event_id);
}

pub(super) fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

pub(super) fn shell_quote_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) const UNAVAILABLE_NETWORK_CHILD: &str = r#"import errno, socket, sys

host, port, marker_path, refusal_path, marker_text = sys.argv[1:]
with open(marker_path, "a", encoding="utf-8") as marker:
    marker.write(marker_text + "\n")

try:
    with socket.create_connection((host, int(port)), timeout=1.0):
        pass
except OSError as error:
    if error.errno == errno.ECONNREFUSED:
        with open(refusal_path, "a", encoding="utf-8") as refusal:
            refusal.write("ECONNREFUSED\n")
        sys.exit(73)
    sys.exit(74 if error.errno == errno.EPERM else 75)
sys.exit(76)
"#;
