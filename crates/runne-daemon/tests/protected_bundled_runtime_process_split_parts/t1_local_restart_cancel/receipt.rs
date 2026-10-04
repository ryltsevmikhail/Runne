#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TaskRunHistoryEvent {
    event_id: runne_runtime_client::CanonicalId,
    sequence: u64,
    event_type: String,
    attempt_id: Option<runne_runtime_client::CanonicalId>,
    kind: runne_runtime_client::TaskRunTimelineKind,
    integrity_digest: [u8; 32],
    canonical_digest: [u8; 32],
}

pub(super) async fn read_taskrun_history(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task_id: runne_runtime_client::CanonicalId,
) -> Vec<TaskRunHistoryEvent> {
    let task_scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::TaskRun,
        task_id,
    );
    let mut replayed = Vec::new();
    client
        .catch_up(task_scope, None, |delivery| {
            if let runne_runtime_client::CanonicalReplayPayload::TaskRun(payload) =
                delivery.event().payload()
            {
                let event = delivery.event();
                replayed.push(TaskRunHistoryEvent {
                    event_id: event.event_id(),
                    sequence: event.sequence(),
                    event_type: event.event_type().to_owned(),
                    attempt_id: payload.attempt_id(),
                    kind: payload.kind(),
                    integrity_digest: *event.integrity_digest(),
                    canonical_digest: *event.canonical_digest(),
                });
            }
            Ok::<_, ()>(())
        })
        .await
        .expect("replay same TaskRun history after reconnect");
    replayed
}

pub(super) async fn assert_replayed_taskrun_history(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task_id: runne_runtime_client::CanonicalId,
    before_disconnect: &[TaskRunHistoryEvent],
) {
    let after_reconnect = read_taskrun_history(client, task_id).await;
    assert_eq!(
        after_reconnect, before_disconnect,
        "all typed event identities, sequences, digests, and payload kinds survive reconnect exactly"
    );
    assert!(
        after_reconnect
            .iter()
            .any(|event| event.kind == runne_runtime_client::TaskRunTimelineKind::Created)
    );
    assert!(
        after_reconnect
            .iter()
            .any(|event| event.kind == runne_runtime_client::TaskRunTimelineKind::AttemptStarted)
    );
}

pub(super) async fn assert_replayed_cancel_and_durable_proof(
    recovered: &runne_runtime_client::AuthenticatedRuntimeClient,
    task_id: runne_runtime_client::CanonicalId,
    cancel: runne_runtime_client::CancelTaskRunRequest,
    ack_version: u64,
    terminal_version: u64,
    output_path: &std::path::Path,
    database: &std::path::Path,
) {
    let replay = recovered
        .cancel_task_run(cancel)
        .await
        .expect("same cancellation command replays after restart");
    assert_eq!(replay.stream_version(), ack_version);
    assert_eq!(
        recovered
            .get_task_run(task_id)
            .await
            .unwrap()
            .stream_version(),
        terminal_version,
        "replay appends no second terminal event"
    );
    let output = std::fs::read_to_string(output_path).unwrap();
    assert_eq!(output.lines().filter(|line| *line == "run").count(), 1);
    assert!(output.contains("leader_started") && output.contains("child_started"));
    verify_cancelled_attempt_and_receipt(task_id, database);
    eprintln!("PASS: protected local-command restart during durable cancellation");
}

pub(super) async fn assert_restarted_cancel_finishes(
    recovered: &runne_runtime_client::AuthenticatedRuntimeClient,
    task_id: runne_runtime_client::CanonicalId,
    cancel: runne_runtime_client::CancelTaskRunRequest,
    ack_version: u64,
    output_path: &std::path::Path,
    database: &std::path::Path,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let terminal = loop {
        let snapshot = recovered.get_task_run(task_id).await.unwrap();
        if snapshot.state() == runne_runtime_client::TaskRunState::Cancelled {
            break snapshot;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    assert_replayed_cancel_and_durable_proof(
        recovered,
        task_id,
        cancel,
        ack_version,
        terminal.stream_version(),
        output_path,
        database,
    )
    .await;
}

fn verify_cancelled_attempt_and_receipt(
    task_id: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
) {
    let task_bytes = uuid::Uuid::parse_str(&task_id.to_string())
        .unwrap()
        .into_bytes();
    let connection = rusqlite::Connection::open(database).expect("read cancellation receipts");
    let (state, exit, area_identity): (String, Option<i32>, Vec<u8>) = connection
        .query_row(
            "SELECT state,exit_code,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("local cancellation fact");
    assert_eq!(state, "cancelled");
    assert_eq!(exit, None, "no process exit is invented after daemon crash");
    let (released, receipt, release): (String, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT o.state,r.terminal_event_id,o.release_event_id
             FROM taskrun_assignment_occupations o
             JOIN taskrun_terminal_settlement_receipts r USING(taskrun_id,fence)
             WHERE o.taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("cancellation settlement receipt");
    assert_eq!(released, "released");
    assert_eq!(receipt, release);
    verify_area_was_removed(&area_identity);
}

fn verify_area_was_removed(area_identity: &[u8]) {
    let managed =
        runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(area_identity)
            .unwrap();
    let root = runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
        .expect("current delegated cgroup root");
    assert!(
        !root
            .remove_area_if_present(managed)
            .expect("exact area already removed")
    );
}
