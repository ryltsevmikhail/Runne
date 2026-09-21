#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{CanonicalId, TaskRunState, TaskRunTerminalResult};

#[tokio::test]
async fn task_run_read_get_running_snapshot_matches_contract() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = support::snapshot_json(
        support::TASK_RUN_ID,
        "running",
        3,
        Some(support::ATTEMPT_ID),
        None,
    );
    let (result, requests) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("running snapshot");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].start_line,
        format!("GET /v1/task-runs/{} HTTP/1.1", support::TASK_RUN_ID)
    );
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    let authorization = requests[0].header("authorization").expect("authorization");
    assert!(authorization.starts_with("GocodeSession "));
    assert_eq!(requests[0].header("x-command-id"), None);
    assert_eq!(requests[0].header("idempotency-key"), None);
    assert_eq!(requests[0].body, "");
    assert_eq!(snapshot.task_run_id(), task_run_id);
    assert_eq!(snapshot.state(), TaskRunState::Running);
    assert_eq!(snapshot.stream_version(), 3);
    assert_eq!(
        snapshot.active_attempt_id(),
        CanonicalId::parse(support::ATTEMPT_ID).ok()
    );
    assert_eq!(snapshot.terminal_result(), None);
}

#[tokio::test]
async fn task_run_read_get_succeeded_snapshot_carries_failure_result() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = support::snapshot_json(
        support::TASK_RUN_ID,
        "succeeded",
        4,
        None,
        Some("{\"type\":\"failure\",\"reason\":\"settled failure\"}"),
    );
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("succeeded snapshot");
    assert_eq!(snapshot.state(), TaskRunState::Succeeded);
    assert_eq!(snapshot.active_attempt_id(), None);
    assert_eq!(
        snapshot.terminal_result(),
        Some(&TaskRunTerminalResult::Failure {
            reason: "settled failure".to_owned()
        })
    );
}

#[tokio::test]
async fn task_run_read_get_accepts_explicit_null_optionals() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = support::snapshot_json(support::TASK_RUN_ID, "created", 1, None, None);
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("created snapshot with explicit nulls");
    assert_eq!(snapshot.task_run_id(), task_run_id);
    assert_eq!(snapshot.state(), TaskRunState::Created);
    assert_eq!(snapshot.stream_version(), 1);
    assert_eq!(snapshot.active_attempt_id(), None);
    assert_eq!(snapshot.terminal_result(), None);
}

#[tokio::test]
async fn task_run_read_list_decodes_snapshots_in_order() {
    let first = support::snapshot_json(support::TASK_RUN_ID, "created", 1, None, None);
    let second = support::snapshot_json(
        support::OTHER_TASK_RUN_ID,
        "running",
        5,
        Some(support::ATTEMPT_ID),
        None,
    );
    let (result, requests) = support::drive(
        support::session(),
        vec![support::ok_json(support::list_json(&[first, second]))],
        |client| async move { client.list_task_runs().await },
    )
    .await;
    let snapshots = result.expect("list snapshots");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].start_line, "GET /v1/task-runs HTTP/1.1");
    assert_eq!(requests[0].header("accept"), Some("application/json"));
    assert_eq!(requests[0].header("x-command-id"), None);
    assert_eq!(requests[0].header("idempotency-key"), None);
    assert_eq!(snapshots.len(), 2);
    assert_eq!(
        snapshots[0].task_run_id(),
        CanonicalId::parse(support::TASK_RUN_ID).expect("first ID")
    );
    assert_eq!(snapshots[0].state(), TaskRunState::Created);
    assert_eq!(snapshots[0].stream_version(), 1);
    assert_eq!(
        snapshots[1].task_run_id(),
        CanonicalId::parse(support::OTHER_TASK_RUN_ID).expect("second ID")
    );
    assert_eq!(snapshots[1].state(), TaskRunState::Running);
    assert_eq!(snapshots[1].stream_version(), 5);
    assert_eq!(
        snapshots[1].active_attempt_id(),
        CanonicalId::parse(support::ATTEMPT_ID).ok()
    );
}

#[tokio::test]
async fn task_run_read_list_accepts_empty_list() {
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json("{\"taskRuns\":[]}")],
        |client| async move { client.list_task_runs().await },
    )
    .await;
    assert_eq!(result.expect("empty list"), Vec::new());
}
