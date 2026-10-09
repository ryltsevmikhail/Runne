use std::path::Path;
use std::time::Duration;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DowngradeReceiptFacts {
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

pub(super) type LocalEffectFacts = (
    runne_runtime_client::LocalExecutionOutcome,
    runne_runtime_client::LocalStopEvidence,
    Option<i32>,
);

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture compares the exact request, terminal, local effect, receipt, and effect markers."
)]
pub(super) async fn assert_replay_is_inert(
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

pub(super) async fn assert_stale_selection_failed(
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

pub(super) async fn assert_stale_request_replay_is_inert(
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

pub(super) fn assert_started_once(path: &Path) {
    assert_eq!(
        std::fs::read_to_string(path).expect("read persistent started marker"),
        "started\n",
        "the started effect remains exactly one append"
    );
}

pub(super) fn read_downgrade_receipt(
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

pub(super) fn assert_downgrade_receipt(
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
