use super::*;
use std::path::Path;

pub(super) fn startup_diagnostic(runtime_root: &Path) -> String {
    super::super::t1_startup_diagnostic::startup_diagnostic(runtime_root)
}

pub(super) async fn remove_owned_area(
    area: runne_platform::process_managed_area::LinuxManagedArea,
    heartbeat: &Path,
) {
    area.terminate(Duration::ZERO)
        .expect("stop only this fixture's exact child cgroup");
    area.remove_empty()
        .expect("remove only this fixture's exact empty cgroup");
    let stopped_at = std::fs::metadata(heartbeat)
        .expect("read heartbeat after private cgroup stop")
        .len();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        std::fs::metadata(heartbeat)
            .expect("read heartbeat after private cgroup cleanup")
            .len(),
        stopped_at,
        "test cleanup leaves no detached child running"
    );
}

pub(super) struct RestartObservation<'a> {
    pub(super) client: &'a runne_runtime_client::AuthenticatedRuntimeClient,
    pub(super) task_id: runne_runtime_client::CanonicalId,
    pub(super) expected_stream_version: u64,
    pub(super) history_before_restart: &'a [super::receipt::TaskRunHistoryEvent],
    pub(super) database: &'a Path,
    pub(super) task_bytes: &'a [u8; 16],
    pub(super) output: &'a Path,
    pub(super) heartbeat: &'a Path,
}

pub(super) async fn assert_unconfirmed_after_restart(observation: RestartObservation<'_>) {
    let RestartObservation {
        client,
        task_id,
        expected_stream_version,
        history_before_restart,
        database,
        task_bytes,
        output,
        heartbeat,
    } = observation;
    let heartbeat_before = std::fs::metadata(heartbeat).unwrap().len();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let effects = loop {
        let snapshot = client.get_task_run(task_id).await.unwrap();
        assert_eq!(
            snapshot.state(),
            runne_runtime_client::TaskRunState::Cancelling
        );
        assert_eq!(snapshot.stream_version(), expected_stream_version);
        let effects = client.get_task_run_effects(task_id).await.unwrap();
        if effects.local_command().is_some_and(|local| {
            local.stop() == runne_runtime_client::LocalStopEvidence::Unconfirmed
        }) {
            break effects;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        effects.local_command().unwrap().outcome(),
        runne_runtime_client::LocalExecutionOutcome::OutcomeUnknown
    );
    assert_eq!(
        effects.remote().outcome(),
        runne_runtime_client::RemoteEffectOutcome::NotApplicable
    );
    super::receipt::assert_replayed_taskrun_history(client, task_id, history_before_restart).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let output_text = std::fs::read_to_string(output).unwrap();
    assert_eq!(output_text.lines().filter(|line| *line == "run").count(), 1);
    assert_eq!(
        std::fs::metadata(heartbeat).unwrap().len(),
        heartbeat_before,
        "the unknown command is not automatically replayed after restart"
    );
    let mut history = Vec::new();
    client
        .catch_up(
            runne_runtime_client::ReplayScope::new(
                runne_runtime_client::ReplayAggregateKind::TaskRun,
                task_id,
            ),
            None,
            |delivery| {
                history.push(delivery.event().event_type().to_owned());
                Ok::<_, ()>(())
            },
        )
        .await
        .unwrap();
    assert!(
        history
            .iter()
            .any(|kind| kind == "taskRun.cancellation.requested")
    );
    assert!(
        !history
            .iter()
            .any(|kind| kind == "taskRun.cancellation.completed")
    );
    assert!(!history.iter().any(|kind| kind == "taskRun.cancelled"));
    assert!(!history.iter().any(|kind| kind == "taskRun.completed"));
    let count: i64 = rusqlite::Connection::open(database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1",
            [task_bytes.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "unproven stop never creates a terminal receipt");
}
